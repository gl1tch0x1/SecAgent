"""Regression tests for scan routing and proof publication."""

import httpx
import json
from pathlib import Path
import pytest

from secagents.armada.swarm import ArmadaOrchestrator
from secagents.core.orchestrator import Intent, Orchestrator
from secagents.crucible.validation import CrucibleValidator
from secagents.modules.cve_checks import CHECKS
from secagents.modules.cve_scanner import CVEScanner, ScanConfig
from secagents.remediation.reporter import ReportGenerator


@pytest.mark.asyncio
async def test_default_scan_routes_to_recon_and_universal_scan(monkeypatch):
    from secagents.core.aura_memory import AuraMemoryManager

    monkeypatch.setattr(
        AuraMemoryManager,
        "get_instance",
        lambda: type("Memory", (), {"recall_target_dna": lambda self, target: None})(),
    )
    graph = Orchestrator().decompose_intent(Intent.SCAN, {"target": "example.com"})
    assert [task.action for task in graph.tasks] == ["full_recon", "universal_scan"]

    armada = ArmadaOrchestrator()
    calls = []

    async def recon(*, context, action):
        calls.append(action)
        return {"findings": []}

    async def scan(*, context, action):
        calls.append(action)
        return {"findings": [{"type": "test"}]}

    armada.register_handler("subdomain", recon)
    armada.register_handler("universal_scan", scan)
    result = await armada.execute(
        armada.plan_mission("example.com"), {"target": "example.com"}
    )
    assert calls == ["full_recon", "universal_scan"]
    assert result["failures"] == []
    assert result["findings"] == [{"type": "test"}]


@pytest.mark.asyncio
async def test_passive_proof_replay_is_typed(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")

    def respond(request):
        return httpx.Response(200, text="OK", headers={"Content-Type": "text/plain"})

    validator = CrucibleValidator()
    await validator.aclose()
    validator._client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        result = await validator.validate_finding(
            {
                "url": "https://example.com/",
                "poc_url": "https://example.com/",
                "check_key": "missing_headers",
                "request_method": "GET",
            }
        )
        assert result["validated"] is True
        assert result["proof"]["policy"] == "missing_headers"
    finally:
        await validator.aclose()


@pytest.mark.asyncio
async def test_untyped_and_browser_only_signals_are_manual_leads(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    validator = CrucibleValidator()
    try:
        outcomes = await validator.validate_batch(
            [
                {
                    "url": "https://example.com/",
                    "source": "arsenal",
                    "proof_signal": "echo",
                },
                {
                    "url": "https://example.com/",
                    "check_key": "xss",
                    "proof_signal": "echo",
                },
            ]
        )
        assert all(item["validation_status"] == "manual_lead" for item in outcomes)
        assert all(not item["validated"] for item in outcomes)
    finally:
        await validator.aclose()


@pytest.mark.asyncio
async def test_stateful_checks_are_skipped_and_post_replay_is_manual(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    scanner = CVEScanner(ScanConfig(target="example.com"))
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, text="ordinary response")

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        nosqli = next(check for check in CHECKS if check.key == "nosqli")
        await scanner._run_check(client, "https://example.com/", nosqli)
    assert requests == []
    assert scanner.progress.skipped_stateful_checks == 2

    validator = CrucibleValidator()
    try:
        result = await validator.validate_finding(
            {
                "url": "https://example.com/",
                "check_key": "nosqli",
                "request_method": "POST",
                "request_data": {"username": "payload"},
            }
        )
        assert result["validation_status"] == "manual_lead"
    finally:
        await validator.aclose()


def test_report_redacts_common_credentials_and_records_coverage(tmp_path):
    paths = ReportGenerator(tmp_path).generate_all(
        "example.com",
        [
            {
                "title": "example",
                "severity": "low",
                "url": "https://example.com/?token=private-value",
                "poc": {"request_headers": {"Authorization": "Bearer private-value"}},
            }
        ],
        manual_leads=[{"title": "lead", "validation_reason": "needs browser proof"}],
        coverage={"skipped_stateful_checks": 2},
    )
    report = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert report["schema_version"] == "1.0"
    assert report["coverage"]["skipped_stateful_checks"] == 2
    assert len(report["manual_leads"]) == 1
    sarif = json.loads(Path(paths["sarif"]).read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    for path in paths.values():
        assert "private-value" not in Path(path).read_text(encoding="utf-8")
