"""Hermetic positive/negative fixtures for scan limits and proof publication."""

import json

import httpx
import pytest

from secagents.crucible.validation import CrucibleValidator
from secagents.crucible.proof_policy import PROOF_POLICIES
from secagents.infra.execution_budget import BudgetExceeded, ExecutionBudget
from secagents.modules.cve_checks import CHECKS, build_payloads
from secagents.modules.cve_scanner import CVEScanner, ScanConfig
from secagents.modules.external_tools import ExternalTools
from secagents.agents.api_security import APISecurityAgent
from secagents.infra.request_inventory import import_har, import_openapi
from secagents.engine.poc_generator import PoCGenerator
from secagents.modules.oast_browser import OASTClient


@pytest.mark.asyncio
async def test_budget_counts_requests_and_stops_at_limit(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    budget = ExecutionBudget(
        max_requests=2, requests_per_second_per_host=1000, max_concurrency=1
    )
    async with budget.request("https://example.com/one"):
        assert budget.snapshot()["peak_concurrency"] == 1
    async with budget.request("https://example.com/two"):
        pass
    with pytest.raises(BudgetExceeded):
        async with budget.request("https://example.com/three"):
            pass
    assert budget.snapshot()["requests_used"] == 2
    assert budget.snapshot()["termination_reason"] == "request_limit_exceeded"


@pytest.mark.asyncio
async def test_unmetered_external_tool_is_skipped(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    monkeypatch.setattr("shutil.which", lambda _: "tool")
    budget = ExecutionBudget(max_requests=2)
    result = await ExternalTools.run("katana", "example.com", budget=budget)
    assert result.success is False
    assert "cannot be counted" in result.raw
    assert budget.snapshot()["requests_used"] == 0


def test_callback_probes_require_proof_capability():
    for key in ("ssrf", "rfi", "log4shell"):
        assert build_payloads(key, "https://example.com/") == []


@pytest.mark.asyncio
async def test_oast_placeholder_does_not_fabricate_callback_url():
    client = OASTClient()
    with pytest.raises(RuntimeError):
        await client.register()
    assert client.callback_url is None


def test_every_registered_check_has_an_explicit_proof_policy():
    assert {check.key for check in CHECKS} == set(PROOF_POLICIES)


@pytest.mark.asyncio
async def test_exposure_check_probes_artifact_not_root(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    urls = []

    def respond(request):
        urls.append(str(request.url))
        if request.url.path == "/.git/config":
            return httpx.Response(200, text="[core]\nrepositoryformatversion = 0")
        return httpx.Response(404, text="[core]")

    scanner = CVEScanner(ScanConfig(target="example.com"))
    git_check = next(check for check in CHECKS if check.key == "git_exposed")
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        result = await scanner._run_check(
            client, "https://example.com/start", git_check
        )
    assert result is not None and result.poc_url == "https://example.com/.git/config"
    assert urls == ["https://example.com/.git/config"]


@pytest.mark.asyncio
async def test_scanner_replaces_existing_query_parameter(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    seen = []

    def respond(request):
        seen.append(str(request.url))
        if request.url.params.get("q") == "1'":
            return httpx.Response(200, text="You have an error in your SQL syntax")
        return httpx.Response(200, text="Normal search results")

    scanner = CVEScanner(ScanConfig(target="example.com"))
    check = next(check for check in CHECKS if check.key == "sqli")
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        result = await scanner._run_check(
            client, "https://example.com/search?q=sample", check
        )
    assert result is not None
    assert "q=sample" not in result.poc_url
    assert any("q=1%27" in url for url in seen)


@pytest.mark.asyncio
async def test_active_proof_needs_negative_control_and_two_replays(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    seen = []

    def respond(request):
        seen.append(str(request.url))
        if "secagent_negative_control" in str(request.url):
            return httpx.Response(200, text="normal")
        return httpx.Response(200, text="You have an error in your SQL syntax")

    validator = CrucibleValidator()
    await validator.aclose()
    validator._client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        outcome = await validator.validate_finding(
            {
                "url": "https://example.com/search",
                "poc_url": "https://example.com/search?q=1%27",
                "check_key": "sqli",
                "request_method": "GET",
                "payload_spec": {"method": "GET", "param": "q", "value": "1'"},
            }
        )
        assert outcome["validated"] is True
        assert [item["role"] for item in outcome["proof"]["observations"]] == [
            "positive_probe",
            "negative_control",
            "positive_replay",
            "positive_replay",
        ]
        assert len(seen) == 4
    finally:
        await validator.aclose()


@pytest.mark.asyncio
async def test_unproven_api_checks_do_not_send_writes_or_publish_findings(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    agent = APISecurityAgent()

    async def unexpected_request(*args, **kwargs):
        raise AssertionError("unproven API heuristic sent a network request")

    monkeypatch.setattr(agent, "_send_api_request", unexpected_request)
    output = await agent.execute(
        {
            "target": "https://example.com",
            "endpoints": [{"method": "DELETE", "path": "/users/1"}],
        }
    )
    assert output.result["findings"] == []
    assert output.result["coverage_gaps"][0]["method"] == "DELETE"


def test_openapi_and_har_keep_methods_and_bodies_without_credentials(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    spec = tmp_path / "openapi.json"
    spec.write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "paths": {
                    "/items": {
                        "get": {},
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {"example": {"name": "test"}}
                                }
                            }
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    templates = import_openapi(spec, "https://example.com/")
    assert [(item.method, item.url) for item in templates] == [
        ("GET", "https://example.com/items"),
        ("POST", "https://example.com/items"),
    ]
    assert json.loads(templates[1].body) == {"name": "test"}

    har = tmp_path / "capture.har"
    har.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "PATCH",
                                "url": "https://example.com/items/1",
                                "headers": [
                                    {"name": "Authorization", "value": "secret"}
                                ],
                                "postData": {"text": '{"name":"updated"}'},
                            }
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    captured = import_har(har)
    assert captured[0].method == "PATCH"
    assert captured[0].body == '{"name":"updated"}'
    assert "secret" not in str(captured[0])


def test_poc_generator_never_calls_reflection_or_difference_exploit_proof(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    generator = PoCGenerator()
    assert (
        generator.generate({"url": "https://example.com", "payload": "echo"})["status"]
        == "manual_lead"
    )
    proof = generator.generate(
        {
            "validated": True,
            "poc": {
                "method": "GET",
                "url": "https://example.com/?q=test",
                "proof_policy": "sqli",
            },
        }
    )
    assert proof["status"] == "replay_available"
    assert "curl_command" not in proof and "python_script" not in proof
