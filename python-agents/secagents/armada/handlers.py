"""Default Armada task handlers wired to real agents and scanners."""

from __future__ import annotations

import os
from typing import Any, Awaitable, Callable

from secagents.modules.autopilot import Autopilot
from secagents.modules.cve_scanner import CVEScanner, ScanConfig


from secagents.agents.web_security import WebSecurityAgent
from secagents.infra.scope import enforce_scope, ScopeViolationError


def cve_result_to_finding(result) -> dict:
    sev = result.severity.value if hasattr(result.severity, "value") else str(result.severity)
    finding_url = (
        result.poc_url
        if (result.payload_spec or {}).get("method") == "GET_PATH"
        else result.target_url
    )
    return {
        "title": result.name,
        "type": result.name,
        "vuln_type": result.name,
        "url": finding_url,
        "location": finding_url,
        "poc_url": result.poc_url,
        "payload": "",
        "evidence": result.proof_signal,
        "proof_signal": result.proof_signal,
        "severity": sev,
        "confidence": 0.95,
        "source": "cve_checks",
        "deterministic": True,
        "check_key": result.check_key,
        "request_method": result.request_method,
        "request_headers": result.request_headers or {},
        "request_data": result.request_data or {},
        "payload_spec": result.payload_spec or {},
    }


def build_scan_handlers(
    shared: dict[str, Any],
) -> dict[str, Callable[..., Awaitable[dict]]]:
    """
    Build handlers that mutate `shared` context:
      target, depth, intel, endpoints, raw_findings, ...
    """

    async def recon_handler(*, context: dict, action: str, **_) -> dict:
        target = context.get("target", shared["target"])
        autopilot = Autopilot(
            target,
            {
                "depth": shared.get("depth", "standard"),
                "intel": shared.get("intel", {}),
                "budget": shared.get("budget"),
            },
        )
        await autopilot._phase_recon()
        raw_endpoints = list(shared.get("endpoints", [])) + autopilot.results.get("endpoints", [])

        # Enforce scope on all discovered endpoints
        scoped_endpoints = []
        for ep in raw_endpoints:
            try:
                enforce_scope(ep)
                scoped_endpoints.append(ep)
            except ScopeViolationError:
                continue

        if not scoped_endpoints:
            scoped_endpoints = [shared.get("target_url", f"https://{target}/")]
        shared["endpoints"] = scoped_endpoints
        shared["autopilot"] = autopilot
        return {"endpoints": len(scoped_endpoints), "findings": []}

    async def scan_handler(*, context: dict, action: str, **_) -> dict:
        target = shared.get("target_url", shared["target"])
        depth = shared.get("depth", "standard")
        threads = 20 if depth == "deep" else 10 if depth == "standard" else 5

        findings: list[dict] = []

        # Deterministic CVE engine (primary)
        scanner = CVEScanner(
            ScanConfig(
                target=target,
                threads=threads,
                timeout=12,
                verify_ssl=os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false",
                seed_urls=shared.get("endpoints", []),
                budget=shared.get("budget"),
                auth_headers=shared.get("auth_headers"),
            )
        )
        progress = await scanner.run()
        if progress.total_urls == 0:
            raise RuntimeError("No live in-scope HTTP endpoints; vulnerability checks did not run")
        for r in progress.findings:
            if r.vulnerable:
                findings.append(cve_result_to_finding(r))

        # Autopilot external tools (nuclei, etc.) when available
        autopilot = shared.get("autopilot")
        if autopilot is None:
            autopilot = Autopilot(target, {"depth": depth, "budget": shared.get("budget")})
            await autopilot._phase_recon()
        await autopilot._phase_scan()
        for f in autopilot.results.get("findings", []):
            if isinstance(f, dict) and f.get("severity", "info") != "info":
                f.setdefault("source", "autopilot")
                findings.append(f)

        shared.setdefault("raw_findings", []).extend(findings)
        return {
            "findings": findings,
            "cve_count": len(progress.findings),
            "candidate_urls": progress.candidate_urls,
            "urls_truncated": progress.urls_truncated,
            "skipped_stateful_checks": progress.skipped_stateful_checks,
            "skipped_callback_checks": progress.skipped_callback_checks,
            "external_tools": autopilot.results.get("phases", {}).get("scan", {}),
        }

    async def specialized_vuln_handler(vuln_type: str, context: dict) -> dict:
        target = shared["target"]
        endpoints = shared.get("endpoints", [f"https://{target}"])

        # Enforce scope on all endpoints before scanning
        scoped_endpoints = []
        for ep in endpoints:
            try:
                enforce_scope(ep)
                scoped_endpoints.append(ep)
            except ScopeViolationError:
                continue

        if not scoped_endpoints:
            scoped_endpoints = [f"https://{target}"]

        agent = WebSecurityAgent()
        out = await agent.execute(
            {
                "target": f"https://{target}",
                "endpoints": scoped_endpoints[:20],
                "vuln_types": [vuln_type],
            }
        )
        findings = out.result.get("findings", []) if isinstance(out.result, dict) else []
        shared.setdefault("raw_findings", []).extend(findings)
        return {"findings": findings, "vuln_type": vuln_type}

    async def sqli_handler(*, context: dict, action: str, **_) -> dict:
        return await specialized_vuln_handler("sqli", context)

    async def xss_handler(*, context: dict, action: str, **_) -> dict:
        return await specialized_vuln_handler("xss", context)

    async def ssrf_handler(*, context: dict, action: str, **_) -> dict:
        return await specialized_vuln_handler("ssrf", context)

    async def idor_handler(*, context: dict, action: str, **_) -> dict:
        return await specialized_vuln_handler("idor", context)

    return {
        "subdomain": recon_handler,
        "web_crawl": recon_handler,
        "port_scan": recon_handler,
        "sqli": sqli_handler,
        "xss": xss_handler,
        "ssrf": ssrf_handler,
        "idor": idor_handler,
        "universal_scan": scan_handler,
    }
