"""Autopilot mode: fully autonomous security assessment pipeline."""

from __future__ import annotations

import json

from secagents.modules.external_tools import ExternalTools
from secagents.modules.exploit_chain import correlate_chains
from secagents.engine.auto_healer import AutoHealer
from secagents.engine.telemetry import TelemetryCollector
from secagents.infra.logging_system import AuditLogger, AuditCategory
from secagents.infra.scope import enforce_scope, ScopeViolationError
from secagents.infra.execution_budget import ExecutionBudget


class Autopilot:
    """Fire-and-forget autonomous security assessment."""

    def __init__(self, target: str, config: dict | None = None):
        self.target = target
        self.config = config or {}
        self.budget: ExecutionBudget | None = self.config.get("budget")
        self._healer = AutoHealer()
        self._telemetry = TelemetryCollector()
        self._logger = AuditLogger.get_instance()
        self.results: dict = {"target": target, "phases": {}, "findings": [], "chains": []}

    async def run(self) -> dict:
        """Execute full autonomous pipeline."""
        self._logger.audit(AuditCategory.SCAN_START, f"Autopilot started for {self.target}")

        await self._phase_recon()
        await self._phase_scan()
        await self._phase_validate()
        await self._phase_correlate()

        self._telemetry.save()
        self._logger.audit(
            AuditCategory.SCAN_COMPLETE,
            f"Autopilot complete: {len(self.results['findings'])} findings",
        )
        return self.results

    async def _phase_recon(self) -> None:
        self._telemetry.record_action("autopilot", "recon_start")
        recon_tools = ["subfinder", "httpx", "katana", "waybackurls"]
        results = await ExternalTools.run_parallel(recon_tools, self.target, self.budget)
        self.results["phases"]["recon"] = {
            t: {"success": r.success, "count": len(r.output)} for t, r in results.items()
        }
        # Collect discovered endpoints (only valid URLs)
        endpoints = set()
        for r in results.values():
            for line in r.output:
                if line.startswith("http"):
                    try:
                        enforce_scope(line)
                        endpoints.add(line)
                    except ScopeViolationError:
                        continue
        self.results["endpoints"] = list(endpoints)[:500]

    async def _phase_scan(self) -> None:
        self._telemetry.record_action("autopilot", "scan_start")
        scan_tools = ["nuclei", "naabu"]
        results = await ExternalTools.run_parallel(scan_tools, self.target, self.budget)
        self.results["phases"]["scan"] = {
            tool: {"success": result.success, "error": "" if result.success else result.raw[:200]}
            for tool, result in results.items()
        }
        for tool, result in results.items():
            for line in result.output:
                try:
                    finding = json.loads(line)
                    self.results["findings"].append(finding)
                except (json.JSONDecodeError, ValueError):
                    if line.strip():
                        self.results["findings"].append(
                            {"title": line, "source": tool, "severity": "info"}
                        )

    async def _phase_validate(self) -> None:
        self._telemetry.record_action("autopilot", "validate_start")
        # Filter out low-confidence findings
        self.results["findings"] = [
            f for f in self.results["findings"] if f.get("severity", "info") != "info"
        ]

    async def _phase_correlate(self) -> None:
        self._telemetry.record_action("autopilot", "correlate_start")
        self.results["chains"] = correlate_chains(self.results["findings"])
