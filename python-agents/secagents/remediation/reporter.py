"""Executive and technical reports in JSON, Markdown, HTML."""

from __future__ import annotations

import html
import csv
import hashlib
import json
import re
import time
from pathlib import Path


SEVERITY_SCORE = {"critical": 10, "high": 7, "medium": 5, "low": 2, "info": 0}
SECRET_FIELDS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "api_key",
        "x-api-key",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "password",
        "secret",
        "client_secret",
        "session",
        "session_id",
        "csrf_token",
        "request_body",
    }
)


def _redact(value):
    """Remove common credential fields from exported report material."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if str(key).lower() in SECRET_FIELDS else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)(Bearer\s+)\S+", r"\1[REDACTED]", value)
        return re.sub(
            r"(?i)([?&](?:api_key|x-api-key|access_token|refresh_token|id_token|token|password|client_secret|secret|session|session_id|csrf_token|key)=)[^&#\s]+",
            r"\1[REDACTED]",
            value,
        )
    return value


class ReportGenerator:
    def __init__(self, output_dir: str | Path = "cog-ai-results/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _risk_score(self, findings: list[dict]) -> float:
        if not findings:
            return 0.0
        return round(
            sum(SEVERITY_SCORE.get(f.get("severity", "info"), 0) for f in findings) / len(findings),
            2,
        )

    def generate_all(
        self,
        target: str,
        findings: list[dict],
        chains: list | None = None,
        manual_leads: list[dict] | None = None,
        coverage: dict | None = None,
    ) -> dict:
        findings = _redact(findings)
        chains = _redact(chains or [])
        manual_leads = _redact(manual_leads or [])
        coverage = _redact(coverage or {})
        target = _redact(target)
        ts = time.strftime("%Y%m%d_%H%M%S")
        base = self.output_dir / f"{target.replace('/', '_')}_{ts}"
        paths = {
            "json": self._write_json(
                base.with_suffix(".json"), target, findings, chains, manual_leads, coverage
            ),
            "markdown": self._write_markdown(
                base.with_suffix(".md"), target, findings, chains, manual_leads, coverage
            ),
            "html": self._write_html(
                base.with_suffix(".html"), target, findings, chains, manual_leads, coverage
            ),
            "csv": self._write_csv(base.with_suffix(".csv"), findings),
            "sarif": self._write_sarif(base.with_suffix(".sarif"), findings),
        }
        return paths

    def _write_csv(self, path: Path, findings: list[dict]) -> str:
        def safe_cell(value: object) -> str:
            cell = str(value)
            return "'" + cell if cell.lstrip().startswith(("=", "+", "-", "@")) else cell

        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=["severity", "title", "url", "proof_policy", "validation_status"],
            )
            writer.writeheader()
            for finding in findings:
                writer.writerow(
                    {
                        key: safe_cell(value)
                        for key, value in {
                            "severity": finding.get("severity", ""),
                            "title": finding.get("title", finding.get("type", "")),
                            "url": finding.get("url", ""),
                            "proof_policy": finding.get("check_key", ""),
                            "validation_status": finding.get("validation_status", ""),
                        }.items()
                    }
                )
        return str(path)

    def _write_sarif(self, path: Path, findings: list[dict]) -> str:
        rules: dict[str, dict] = {}
        results = []
        for finding in findings:
            rule_id = str(finding.get("check_key") or finding.get("type") or "unknown")
            rules.setdefault(rule_id, {"id": rule_id, "name": rule_id})
            url = str(finding.get("url", ""))
            fingerprint = hashlib.sha256(
                f"{rule_id}|{url}|{finding.get('parameter', '')}".encode()
            ).hexdigest()
            severity = str(finding.get("severity", "low")).lower()
            level = (
                "error"
                if severity in {"critical", "high"}
                else "warning"
                if severity == "medium"
                else "note"
            )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": str(finding.get("title", rule_id))},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": url}}}],
                    "partialFingerprints": {"secagent/v1": fingerprint},
                }
            )
        doc = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "SecAgent", "rules": list(rules.values())}},
                    "results": results,
                }
            ],
        }
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return str(path)

    def _write_json(
        self,
        path: Path,
        target: str,
        findings: list,
        chains: list | None,
        manual_leads: list | None = None,
        coverage: dict | None = None,
    ) -> str:
        doc = {
            "schema_version": "1.0",
            "target": target,
            "generated_at": time.time(),
            "risk_score": self._risk_score(findings),
            "findings": findings,
            "attack_chains": chains or [],
            "manual_leads": manual_leads or [],
            "coverage": coverage or {},
        }
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return str(path)

    def _write_markdown(
        self,
        path: Path,
        target: str,
        findings: list,
        chains: list | None,
        manual_leads: list | None = None,
        coverage: dict | None = None,
    ) -> str:
        lines = [
            f"# Security Assessment: {target}",
            f"**Risk Score:** {self._risk_score(findings)}/10",
            "",
            "## Executive Summary",
            f"- Validated findings: {len(findings)}",
            f"- Manual or inconclusive leads: {len(manual_leads or [])}",
            f"- Failed scan tasks: {len((coverage or {}).get('armada_failures', []))}",
            f"- HTTP requests used: {(coverage or {}).get('budget', {}).get('requests_used', 'unknown')}",
            f"- Budget termination: {(coverage or {}).get('budget', {}).get('termination_reason') or 'none'}",
            "",
            "## Findings",
        ]
        for f in findings:
            poc = f.get("poc", {})
            replay = (
                f"{poc.get('method', 'GET')} {poc.get('url', '')} (policy: {poc.get('proof_policy', 'unknown')})"
                if isinstance(poc, dict)
                else "N/A"
            )
            lines.extend(
                [
                    f"### {f.get('title', f.get('vuln_type', 'Finding'))}",
                    f"- **Severity:** {f.get('severity', 'unknown')}",
                    f"- **URL:** {f.get('url', 'N/A')}",
                    f"- **Replay:** `{replay}`",
                    f"- **Proof:** {f.get('proof', {}).get('signal', 'See JSON evidence')}",
                    f"- **Remediation:** {f.get('remediation', f.get('remediation_patch', {}).get('patch_snippet', 'See patch'))}",
                    "",
                ]
            )
        if chains:
            lines.append("## Attack Chains")
            for c in chains:
                lines.append(f"- {c}")
        if manual_leads:
            lines.append("## Manual and Inconclusive Leads")
            for lead in manual_leads:
                lines.append(
                    f"- {lead.get('title', lead.get('type', 'Candidate'))}: {lead.get('validation_reason', 'Further proof needed')}"
                )
        if coverage and coverage.get("armada_failures"):
            lines.append("## Incomplete Coverage")
            for failure in coverage["armada_failures"]:
                lines.append(
                    f"- {failure.get('action', 'task')}: {failure.get('error', failure.get('reason', 'failed'))}"
                )
        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path)

    def _write_html(
        self,
        path: Path,
        target: str,
        findings: list,
        chains: list | None,
        manual_leads: list | None = None,
        coverage: dict | None = None,
    ) -> str:
        rows = "".join(
            f"<tr><td>{html.escape(str(f.get('severity', '')))}</td>"
            f"<td>{html.escape(str(f.get('title', f.get('vuln_type', ''))))}</td>"
            f"<td>{html.escape(str(f.get('url', '')))}</td>"
            f"<td>{html.escape(str(f.get('proof', {}).get('policy', '')))}</td>"
            f"<td>{html.escape(str(f.get('proof', {}).get('signal', '')))}</td></tr>"
            for f in findings
        )
        doc = f"""<!DOCTYPE html>
<html><head><title>SecAgent Report — {html.escape(target)}</title>
<style>body{{font-family:sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ccc;padding:8px}}th{{background:#1a1a2e;color:#fff}}</style></head>
<body><h1>SecAgent Report: {html.escape(target)}</h1>
<p>Risk Score: <strong>{self._risk_score(findings)}</strong></p>
<p>Validated findings: {len(findings)} · Manual leads: {len(manual_leads or [])} · Failed scan tasks: {len((coverage or {}).get("armada_failures", []))}</p>
<p>HTTP requests used: {(coverage or {}).get("budget", {}).get("requests_used", "unknown")} · Budget termination: {html.escape(str((coverage or {}).get("budget", {}).get("termination_reason") or "none"))}</p>
<table><tr><th>Severity</th><th>Title</th><th>URL</th><th>Proof policy</th><th>Observation</th></tr>{rows}</table>
</body></html>"""
        path.write_text(doc, encoding="utf-8")
        return str(path)
