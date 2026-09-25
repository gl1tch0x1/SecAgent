"""Recon agent for attack surface discovery."""

import asyncio
import logging
import os
import re
import httpx

from secagents.agents.base import BaseAgent, AgentConfig, AgentOutput, AgentRole
from secagents.prompts import RECON_PROMPT
from secagents.infra.scope import enforce_scope, ScopeViolationError, normalize_target
from secagents.infra.execution_budget import ExecutionBudget

logger = logging.getLogger(__name__)


class ReconAgent(BaseAgent):
    """Discovers attack surface: subdomains, endpoints, parameters.

    Responsibilities:
    - Subdomain enumeration
    - HTTP probing
    - URL crawling
    - Parameter discovery
    - Asset inventory
    """

    def __init__(self):
        super().__init__(
            AgentConfig(
                role=AgentRole.RECON,
                name="recon",
                tools=["subdomain_enum", "http_probe", "crawl", "param_discovery"],
                timeout_seconds=300.0,
            )
        )
        self.logger = logging.getLogger("secagents.recon")
        self.budget = ExecutionBudget(max_requests=100, max_duration_seconds=60)

    async def _get(self, client: httpx.AsyncClient, url: str) -> httpx.Response:
        async with self.budget.request(url):
            return await client.get(url)

    def base_system_prompt(self) -> str:
        """Return the recon agent's system prompt."""
        return RECON_PROMPT

    async def execute(self, task: dict) -> AgentOutput:
        """Execute recon actions to discover attack surface."""
        action = task.get("action", "full_recon")
        target = task.get("target", "")

        if not target:
            self.logger.error("No target specified")
            return self._format_output(
                result={"error": "target required"},
                confidence=0.0,
                reasoning="Missing required target parameter",
            )

        self.logger.info(f"Starting {action} on {target}")

        try:
            enforce_scope(target)
            self.budget = ExecutionBudget(max_requests=100, max_duration_seconds=60)
            if action == "subdomain_enum":
                results = await self._subdomain_enum(target)
            elif action == "http_probe":
                results = await self._http_probe(target)
            elif action == "crawl":
                results = await self._crawl(target)
            elif action == "param_discovery":
                results = await self._param_discovery(target)
            elif action == "full_recon":
                results = await self._full_recon(target)
            else:
                return self._format_output(
                    result={"error": f"unknown action: {action}"},
                    confidence=0.0,
                    reasoning="Invalid action specified",
                )

            confidence = self._calculate_confidence(
                evidence_count=len(results.get("findings", [])),
                max_evidence=50,
                base_confidence=0.7,
            )

            return self._format_output(
                result=results,
                confidence=confidence,
                reasoning=f"Completed {action} on {target}",
                metadata={"action": action, "target": target},
            )
        except Exception as e:
            self.logger.error(f"Recon failed: {str(e)}", exc_info=True)
            return self._format_output(
                result={"error": str(e)},
                confidence=0.0,
                reasoning="Recon execution failed",
            )

    async def _full_recon(self, target: str) -> dict:
        """Execute full reconnaissance workflow.

        Args:
            target: Target domain/URL

        Returns:
            Aggregated recon findings
        """
        self.logger.info(f"Running full recon on {target}")

        try:
            # Run tasks concurrently
            tasks = [
                self._subdomain_enum(target),
                self._http_probe(target),
                self._crawl(target),
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            findings = []
            for result in results:
                if isinstance(result, Exception):
                    self.logger.warning(f"Task failed: {str(result)}")
                elif isinstance(result, dict):
                    findings.extend(result.get("findings", []))

            return {
                "action": "full_recon",
                "target": target,
                "status": "completed",
                "findings": findings,
                "finding_count": len(findings),
            }
        except Exception as e:
            self.logger.error(f"Full recon failed: {str(e)}")
            return {
                "action": "full_recon",
                "target": target,
                "status": "failed",
                "error": str(e),
                "findings": [],
            }

    async def _subdomain_enum(self, target: str) -> dict:
        """Enumerate subdomains for target using active DNS & web probes."""
        self.logger.info(f"Enumerating subdomains for {target}")
        prefixes = ["api", "admin", "staging", "dev", "www", "app", "portal", "mail", "v1", "test"]
        findings = []

        clean_target = normalize_target(target)

        async def _check_sub(prefix: str):
            sub = f"{prefix}.{clean_target}"
            url = f"https://{sub}"
            try:
                enforce_scope(url)
            except ScopeViolationError:
                return None
            from secagents.core.native import native_engine

            # Fast C++ socket probe before full HTTP request
            async with self.budget.request(url):
                probe_res = native_engine.probe_port(sub, 443, timeout_ms=1000)
            if not probe_res.get("open", False):
                async with self.budget.request(f"http://{sub}"):
                    probe_res = native_engine.probe_port(sub, 80, timeout_ms=1000)
                if not probe_res.get("open", False):
                    return None

            verify_ssl = os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false"
            try:
                async with httpx.AsyncClient(
                    timeout=3.0, verify=verify_ssl, follow_redirects=False
                ) as client:
                    resp = await self._get(client, url)
                    return {
                        "type": "subdomain",
                        "value": sub,
                        "metadata": {
                            "discovery_method": "native_cpp_probe",
                            "status_code": resp.status_code,
                            "latency_ms": probe_res.get("latency_ms", 0),
                        },
                        "priority": "high" if prefix in ["api", "admin"] else "medium",
                    }
            except Exception:
                return {
                    "type": "subdomain",
                    "value": sub,
                    "metadata": {
                        "discovery_method": "native_cpp_socket_open",
                        "latency_ms": probe_res.get("latency_ms", 0),
                    },
                    "priority": "medium",
                }

        tasks = [_check_sub(p) for p in prefixes]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, dict) and res:
                # Validate discovered subdomain against ALLOWED_DOMAINS
                try:
                    enforce_scope(res["value"])
                    findings.append(res)
                except ScopeViolationError:
                    self.logger.debug(f"Subdomain {res['value']} filtered by scope policy")
                    continue

        self.logger.info(f"Found {len(findings)} resolved subdomains")
        return {
            "action": "subdomain_enum",
            "target": target,
            "status": "completed",
            "findings": findings,
        }

    async def _http_probe(self, target: str) -> dict:
        """Probe target host for active HTTP/HTTPS services."""
        self.logger.info(f"Probing HTTP services for {target}")
        findings = []
        clean_target = normalize_target(target)
        verify_ssl = os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false"

        for scheme in ["https", "http"]:
            url = f"{scheme}://{clean_target}"
            try:
                async with httpx.AsyncClient(
                    timeout=4.0, verify=verify_ssl, follow_redirects=False
                ) as client:
                    resp = await self._get(client, url)
                    server_header = resp.headers.get("server", "Unknown")
                    title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE)
                    page_title = title_match.group(1).strip() if title_match else "No Title"

                    findings.append(
                        {
                            "type": "http_service",
                            "url": str(resp.url),
                            "status_code": resp.status_code,
                            "title": page_title,
                            "technology": server_header,
                            "priority": "high" if resp.status_code == 200 else "medium",
                        }
                    )
            except Exception as e:
                self.logger.debug(f"HTTP probe failed for {url}: {e}")

        self.logger.info(f"Found {len(findings)} active HTTP services")
        return {
            "action": "http_probe",
            "target": target,
            "status": "completed",
            "findings": findings,
        }

    async def _crawl(self, target: str) -> dict:
        """Real asynchronous web crawler extracting active links and forms."""
        self.logger.info(f"Crawling target: {target}")
        findings = []
        base_url = target if target.startswith("http") else f"https://{target}"
        verify_ssl = os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false"

        try:
            async with httpx.AsyncClient(
                timeout=5.0, verify=verify_ssl, follow_redirects=False
            ) as client:
                resp = await self._get(client, base_url)
                if resp.status_code == 200:
                    # Extract links from href attributes
                    links = set(re.findall(r'href=["\'](/[^"\']+)["\']', resp.text))
                    for path in list(links)[:20]:
                        findings.append(
                            {
                                "type": "endpoint",
                                "path": path,
                                "method": "GET",
                                "status_code": 200,
                                "priority": "high"
                                if any(k in path for k in ["admin", "api", "login"])
                                else "medium",
                            }
                        )
        except Exception as e:
            self.logger.warning(f"Crawl failed on {target}: {e}")

        self.logger.info(f"Discovered {len(findings)} endpoints")
        return {
            "action": "crawl",
            "target": target,
            "status": "completed",
            "findings": findings,
        }

    async def _param_discovery(self, target: str) -> dict:
        """Discover GET & POST query parameters from crawling target response."""
        self.logger.info(f"Discovering parameters for {target}")
        findings = []
        base_url = target if target.startswith("http") else f"https://{target}"
        verify_ssl = os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false"

        try:
            async with httpx.AsyncClient(
                timeout=4.0, verify=verify_ssl, follow_redirects=False
            ) as client:
                resp = await self._get(client, base_url)
                # Find input names from HTML form fields
                inputs = set(
                    re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
                )
                for param in list(inputs)[:10]:
                    findings.append(
                        {
                            "type": "parameter",
                            "endpoint": base_url,
                            "parameter": param,
                            "method": "POST",
                            "location": "body",
                            "priority": "high",
                        }
                    )
        except Exception as e:
            self.logger.debug(f"Param discovery failed on {target}: {e}")

        self.logger.info(f"Discovered {len(findings)} request parameters")
        return {
            "action": "param_discovery",
            "target": target,
            "status": "completed",
            "findings": findings,
        }
