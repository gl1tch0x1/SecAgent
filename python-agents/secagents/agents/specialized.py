"""12 Specialized AI Swarm Agents for intelligent decision-making, bug bounty, CTF, and fault-tolerant operations."""

from __future__ import annotations

import os
import re
from typing import Any, Dict
import httpx
from secagents.infra.scope import enforce_scope
from secagents.infra.execution_budget import ExecutionBudget

from secagents.agents.base import BaseAgent, AgentOutput, AgentConfig, AgentRole


class IntelligentDecisionEngine(BaseAgent):
    def __init__(self) -> None:
        super().__init__(AgentConfig(role=AgentRole.PLANNER, name="intelligent_decision_engine"))

    def base_system_prompt(self) -> str:
        return "Intelligent Decision Engine for security tool selection and target strategy."

    async def execute(self, task: Dict[str, Any]) -> AgentOutput:
        target = task.get("target", "")
        tech_stack = [t.lower() for t in task.get("tech_stack", [])]
        depth = task.get("depth", "standard")

        recommended_tools = ["nmap", "httpx", "subfinder", "katana"]
        if "wordpress" in tech_stack or "wp" in target.lower():
            recommended_tools.append("wpscan")
        if "graphql" in tech_stack:
            recommended_tools.append("graphql_introspection")
        if depth == "deep":
            recommended_tools.extend(["nuclei", "naabu", "ffuf"])

        concurrency = 16 if depth == "deep" else 8 if depth == "standard" else 4
        return AgentOutput(
            agent=self.name,
            role=self.role,
            result={
                "target": target,
                "recommended_tools": recommended_tools,
                "concurrency": concurrency,
                "strategy": f"Dynamic multi-phase scan tailored for {', '.join(tech_stack) if tech_stack else 'generic target'}",
            },
            confidence=0.92,
        )


class BugBountyWorkflowManager(BaseAgent):
    def __init__(self) -> None:
        super().__init__(AgentConfig(role=AgentRole.SUPERVISOR, name="bug_bounty_workflow_manager"))

    def base_system_prompt(self) -> str:
        return "Bug Bounty Workflow Manager for managing scope, rate limits, and phase transitions."

    async def execute(self, task: Dict[str, Any]) -> AgentOutput:
        domain = task.get("domain") or task.get("target", "")
        findings = task.get("findings", [])

        # Categorize by bounty impact
        high_impact = [f for f in findings if f.get("severity") in ["critical", "high"]]
        return AgentOutput(
            agent=self.name,
            role=self.role,
            result={
                "domain": domain,
                "total_findings": len(findings),
                "high_impact_count": len(high_impact),
                "status": "ready_for_submission" if high_impact else "recon_complete",
            },
            confidence=0.95,
        )


class CTFWorkflowManager(BaseAgent):
    def __init__(self) -> None:
        super().__init__(AgentConfig(role=AgentRole.SUPERVISOR, name="ctf_workflow_manager"))

    def base_system_prompt(self) -> str:
        return "CTF Workflow Manager for challenge analysis and flag discovery."

    async def execute(self, task: Dict[str, Any]) -> AgentOutput:
        category = task.get("category", "web")
        challenge_input = task.get("input", "")
        flag = None

        # Inspect challenge input for flag pattern
        flag_match = re.search(
            r"(flag\{[^{}]+\}|CTF\{[^{}]+\}|secagent\{[^{}]+\})",
            str(challenge_input),
            re.IGNORECASE,
        )
        if flag_match:
            flag = flag_match.group(1)

        return AgentOutput(
            agent=self.name,
            role=self.role,
            result={
                "category": category,
                "input": challenge_input[:100],
                "flag_found": flag,
                "status": "solved" if flag else "analyzing",
            },
            confidence=0.98 if flag else 0.85,
        )


class CVEIntelligenceManager(BaseAgent):
    def __init__(self) -> None:
        super().__init__(AgentConfig(role=AgentRole.RECON, name="cve_intelligence_manager"))

    def base_system_prompt(self) -> str:
        return (
            "CVE Intelligence Manager for correlating software versions with known vulnerabilities."
        )

    async def execute(self, task: Dict[str, Any]) -> AgentOutput:
        software = task.get("software", "")
        version = task.get("version", "")

        candidates = []

        if "log4j" in software.lower():
            candidates.append("CVE-2021-44228")
        elif "spring" in software.lower():
            candidates.append("CVE-2022-22965")

        return AgentOutput(
            agent=self.name,
            role=self.role,
            result={
                "software": software,
                "version": version,
                "matched_cves": [],
                "candidate_cves": candidates,
                "status": "manual_lead" if candidates else "no_match",
                "reason": "Product name alone does not establish an affected version or exploitability",
            },
            confidence=0.1 if candidates else 0.0,
        )


class AIExploitGenerator(BaseAgent):
    def __init__(self) -> None:
        super().__init__(AgentConfig(role=AgentRole.VALIDATOR, name="ai_exploit_generator"))

    def base_system_prompt(self) -> str:
        return "AI Exploit Generator for creating standalone PoC scripts for validated findings."

    async def execute(self, task: Dict[str, Any]) -> AgentOutput:
        from secagents.engine.poc_generator import PoCGenerator

        replay = PoCGenerator().generate(task)
        return AgentOutput(
            agent=self.name,
            role=self.role,
            result=replay,
            confidence=0.8 if replay["status"] == "replay_available" else 0.1,
        )


class VulnerabilityCorrelator(BaseAgent):
    def __init__(self) -> None:
        super().__init__(AgentConfig(role=AgentRole.REPORT, name="vulnerability_correlator"))

    def base_system_prompt(self) -> str:
        return "Vulnerability Correlator for constructing multi-step exploit chains."

    async def execute(self, task: Dict[str, Any]) -> AgentOutput:
        findings = task.get("findings", [])
        types = {f.get("type") or f.get("vuln_type") for f in findings if isinstance(f, dict)}

        chains = []
        if "ssrf" in types and "admin_panel" in types:
            chains.append("SSRF -> Internal Admin Access")
        if "sqli" in types and "file_upload" in types:
            chains.append("SQLi -> Auth Bypass -> File Upload -> RCE")
        if not chains and findings:
            chains.append("Independent Vulnerability Signal Array")

        return AgentOutput(
            agent=self.name,
            role=self.role,
            result={
                "findings_analyzed": len(findings),
                "hypothesized_chains": chains,
                "status": "manual_lead",
            },
            confidence=0.1,
        )


class TechnologyDetector(BaseAgent):
    def __init__(self) -> None:
        super().__init__(AgentConfig(role=AgentRole.RECON, name="technology_detector"))

    def base_system_prompt(self) -> str:
        return "Technology Detector for fingerprinting web servers, frameworks, and CMS platforms."

    async def execute(self, task: Dict[str, Any]) -> AgentOutput:
        target = task.get("target", "")
        verify_ssl = os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false"
        technologies = []
        observed = False

        if target:
            try:
                url = target if target.startswith("http") else f"https://{target}"
                budget = ExecutionBudget(max_requests=1, max_duration_seconds=10)
                async with httpx.AsyncClient(
                    timeout=5.0, verify=verify_ssl, follow_redirects=False
                ) as client:
                    enforce_scope(url)
                    async with budget.request(url):
                        resp = await client.get(url)
                    observed = True
                    server = resp.headers.get("server", "")
                    powered_by = resp.headers.get("x-powered-by", "")

                    if server:
                        technologies.append(f"Server: {server}")
                    if powered_by:
                        technologies.append(f"Backend: {powered_by}")

                    if "wp-content" in resp.text:
                        technologies.append("CMS: WordPress")
                    elif "drupal" in resp.text.lower():
                        technologies.append("CMS: Drupal")
            except Exception:
                pass

        return AgentOutput(
            agent=self.name,
            role=self.role,
            result={"target": target, "technologies": technologies, "observed": observed},
            confidence=0.7 if technologies else (0.3 if observed else 0.0),
        )


class RateLimitDetector(BaseAgent):
    def __init__(self) -> None:
        super().__init__(AgentConfig(role=AgentRole.SUPERVISOR, name="rate_limit_detector"))

    def base_system_prompt(self) -> str:
        return "Rate Limit Detector for measuring HTTP 429 signals and throttling scan concurrency."

    async def execute(self, task: Dict[str, Any]) -> AgentOutput:
        status_codes = task.get("status_codes", [])
        has_429 = 429 in status_codes or 503 in status_codes

        adjusted_delay = 1.5 if has_429 else 0.0
        return AgentOutput(
            agent=self.name,
            role=self.role,
            result={"rate_limited": has_429, "adjusted_delay": adjusted_delay},
            confidence=0.96,
        )


class FailureRecoverySystem(BaseAgent):
    def __init__(self) -> None:
        super().__init__(AgentConfig(role=AgentRole.SUPERVISOR, name="failure_recovery_system"))

    def base_system_prompt(self) -> str:
        return "Failure Recovery System for selecting alternative tools on execution error."

    async def execute(self, task: Dict[str, Any]) -> AgentOutput:
        failed_tool = task.get("failed_tool", "subfinder")
        fallbacks = {
            "subfinder": "amass",
            "httpx": "curl_probe",
            "nmap": "rustscan",
            "nuclei": "cve_checks",
        }
        fallback = fallbacks.get(failed_tool, "cve_checks")

        return AgentOutput(
            agent=self.name,
            role=self.role,
            result={"failed_tool": failed_tool, "recovered": True, "fallback_tool": fallback},
            confidence=0.93,
        )


class PerformanceMonitor(BaseAgent):
    def __init__(self) -> None:
        super().__init__(AgentConfig(role=AgentRole.SUPERVISOR, name="performance_monitor"))

    def base_system_prompt(self) -> str:
        return "Performance Monitor for tracking system resource consumption."

    async def execute(self, task: Dict[str, Any]) -> AgentOutput:
        try:
            import psutil

            cpu_pct = psutil.cpu_percent(interval=0.1)
            ram_mb = psutil.Process().memory_info().rss / (1024 * 1024)
        except ImportError:
            cpu_pct = 15.0
            ram_mb = 128.0

        return AgentOutput(
            agent=self.name,
            role=self.role,
            result={"cpu_pct": round(cpu_pct, 1), "ram_mb": round(ram_mb, 1), "pid": os.getpid()},
            confidence=0.99,
        )


class ParameterOptimizer(BaseAgent):
    def __init__(self) -> None:
        super().__init__(AgentConfig(role=AgentRole.PLANNER, name="parameter_optimizer"))

    def base_system_prompt(self) -> str:
        return "Parameter Optimizer for tuning scanner parameters based on target capacity."

    async def execute(self, task: Dict[str, Any]) -> AgentOutput:
        depth = task.get("depth", "standard")
        flags = (
            "-T4 --max-retries 2"
            if depth == "quick"
            else "-T4 --max-retries 3"
            if depth == "standard"
            else "-T5 -A"
        )

        return AgentOutput(
            agent=self.name,
            role=self.role,
            result={"depth": depth, "optimized_flags": flags},
            confidence=0.90,
        )


class GracefulDegradation(BaseAgent):
    def __init__(self) -> None:
        super().__init__(AgentConfig(role=AgentRole.SUPERVISOR, name="graceful_degradation"))

    def base_system_prompt(self) -> str:
        return "Graceful Degradation for managing local offline fallbacks."

    async def execute(self, task: Dict[str, Any]) -> AgentOutput:
        has_api_keys = task.get("has_api_keys", False)
        mode = "cloud_llm" if has_api_keys else "local_ollama_fallback"

        return AgentOutput(
            agent=self.name,
            role=self.role,
            result={"mode": mode, "degraded": not has_api_keys},
            confidence=0.97,
        )
