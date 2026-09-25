"""Repeatable positive/negative proof corpus with resource accounting."""

from __future__ import annotations

import httpx
import pytest
import json
from urllib.parse import urlsplit

from secagents.crucible.validation import CrucibleValidator
from secagents.infra.execution_budget import ExecutionBudget
from secagents.modules.cve_checks import RUN_CANARY
from secagents.crucible.identity_proof import IdentityContract, prove_identity
from secagents.crucible.state_contract import StateContract, observe_state_contract
from secagents.crucible.oast_proof import SSRFContract, prove_ssrf
from secagents.modules.oast_browser import OASTClient


CASES = (
    ("sqli", "/sqli-positive", True),
    ("sqli", "/sqli-negative", False),
    ("git_exposed", "/git-positive/.git/config", True),
    ("git_exposed", "/git-negative/.git/config", False),
    ("missing_headers", "/headers-positive", True),
    ("missing_headers", "/headers-negative", False),
)


def _fixture_response(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path.startswith("/sqli-"):
        injected = request.url.params.get("q") == "1'"
        body = (
            "You have an error in your SQL syntax"
            if path == "/sqli-positive" and injected
            else "Normal search results"
        )
        return httpx.Response(200, text=body)
    if path.endswith("/.git/config"):
        body = (
            "[core]\nrepositoryformatversion = 0" if "git-positive" in path else "safe"
        )
        return httpx.Response(200, text=body)
    if path == "/headers-positive":
        return httpx.Response(200, text="safe")
    if path == "/headers-negative":
        return httpx.Response(
            200,
            text="safe",
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            },
        )
    return httpx.Response(404)


@pytest.mark.asyncio
async def test_http_proof_corpus_precision_recall_and_request_use(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    budget = ExecutionBudget(
        max_requests=40,
        requests_per_second_per_host=1000,
        max_concurrency=2,
    )
    validator = CrucibleValidator(budget=budget)
    await validator.aclose()
    validator._client = httpx.AsyncClient(
        transport=httpx.MockTransport(_fixture_response)
    )
    truth = []
    predicted = []
    try:
        for key, path, expected in CASES:
            base = "https://example.com" + path
            candidate = {
                "url": base,
                "poc_url": base + "?q=1%27" if key == "sqli" else base,
                "check_key": key,
                "request_method": "GET",
                "payload_spec": (
                    {"method": "GET", "param": "q", "value": "1'"}
                    if key == "sqli"
                    else {"method": "GET_PATH", "path": "/.git/config"}
                    if key == "git_exposed"
                    else {}
                ),
            }
            result = await validator.validate_finding(candidate)
            truth.append(expected)
            predicted.append(bool(result["validated"]))
    finally:
        await validator.aclose()

    true_positives = sum(a and b for a, b in zip(truth, predicted))
    false_positives = sum(not a and b for a, b in zip(truth, predicted))
    false_negatives = sum(a and not b for a, b in zip(truth, predicted))
    assert true_positives == 3
    assert false_positives == 0
    assert false_negatives == 0
    assert budget.snapshot()["requests_used"] <= 14


@pytest.mark.asyncio
async def test_provider_budget_uses_exact_host_allowlist(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    budget = ExecutionBudget(max_requests=1)
    async with budget.provider_request("https://api.shodan.io/dns/domain/example.com"):
        pass
    assert budget.snapshot()["requests_used"] == 1
    with pytest.raises(PermissionError):
        async with budget.provider_request("https://api.shodan.io.evil.test/"):
            pass
    assert budget.snapshot()["requests_used"] == 1


@pytest.mark.asyncio
async def test_xss_browser_proof_wiring_requires_reproducible_evidence(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    calls = []

    async def fake_browser(url, payload, budget, auth_headers):
        calls.append((url, payload))
        return {
            "validated": False,
            "reason": "Negative control also executed the canary",
            "observations": [
                {"role": "negative_control", "canary_dialog": True},
                {"role": "positive_probe", "canary_dialog": True},
            ],
        }

    monkeypatch.setattr("secagents.crucible.validation.prove_xss", fake_browser)
    validator = CrucibleValidator()
    try:
        result = await validator.validate_finding(
            {
                "url": "https://example.com/search",
                "poc_url": "https://example.com/search?q=payload",
                "check_key": "xss",
                "payload_spec": {"method": "GET", "param": "q", "value": RUN_CANARY},
            }
        )
    finally:
        await validator.aclose()
    assert len(calls) == 1
    assert result["validated"] is False
    assert result["proof"]["observations"][0]["role"] == "negative_control"


@pytest.mark.asyncio
@pytest.mark.parametrize("cross_identity_leak", [True, False])
async def test_identity_contract_needs_two_identities_and_clean_controls(
    monkeypatch, cross_identity_leak
):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    monkeypatch.setenv("OWNER_AUTH", "Authorization: Bearer owner-secret")
    monkeypatch.setenv("OTHER_AUTH", "Authorization: Bearer other-secret")
    marker = "private-owner-marker"

    def respond(request):
        auth = request.headers.get("authorization", "")
        if request.url.path == "/owner" and auth == "Bearer owner-secret":
            return httpx.Response(200, text=marker)
        if request.url.path == "/owner" and auth == "Bearer other-secret":
            return (
                httpx.Response(200, text=marker)
                if cross_identity_leak
                else httpx.Response(403)
            )
        if request.url.path == "/other" and auth == "Bearer other-secret":
            return httpx.Response(200, text="other account data")
        return httpx.Response(401)

    budget = ExecutionBudget(max_requests=8, requests_per_second_per_host=1000)
    contract = IdentityContract(
        owner_url="https://example.com/owner",
        other_control_url="https://example.com/other",
        private_marker=marker,
        owner_header_env="OWNER_AUTH",
        other_header_env="OTHER_AUTH",
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        result = await prove_identity(contract, budget, client=client)
    assert result["validated"] is cross_identity_leak
    assert budget.snapshot()["requests_used"] == 8
    assert marker not in str(result)
    assert "owner-secret" not in str(result)


@pytest.mark.asyncio
async def test_state_contract_restores_after_control_and_each_probe(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    monkeypatch.setenv("STATE_AUTH", "Authorization: Bearer state-secret")
    state = {"value": "baseline-value"}
    writes = []

    def respond(request):
        if request.method == "GET":
            return httpx.Response(200, text=state["value"])
        if request.method == "POST":
            value = request.content.decode()
            writes.append(value)
            state["value"] = value
            return httpx.Response(200)
        return httpx.Response(405)

    contract = StateContract(
        read_url="https://example.com/state",
        write_url="https://example.com/state",
        write_method="POST",
        control_body="baseline-value",
        probe_body="probe-value",
        cleanup_url="https://example.com/state",
        cleanup_method="POST",
        cleanup_body="baseline-value",
        baseline_marker="baseline-value",
        probe_marker="probe-value",
        header_env="STATE_AUTH",
    )
    budget = ExecutionBudget(max_requests=13, requests_per_second_per_host=1000)
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        result = await observe_state_contract(contract, budget, client=client)
    assert result["proof"]["controlled_state_change"] is True
    assert result["validated"] is False
    assert result["validation_status"] == "manual_lead"
    assert state["value"] == "baseline-value"
    assert len(writes) == 6
    assert budget.snapshot()["requests_used"] == 13
    assert "state-secret" not in str(result)


@pytest.mark.asyncio
async def test_oast_proof_requires_scan_bound_independent_callbacks(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    monkeypatch.setenv("OAST_PROVIDER_DOMAINS", "provider.example")
    monkeypatch.setenv("OAST_CALLBACK_DOMAINS", "callback.example")
    monkeypatch.setenv("OAST_TOKEN", "provider-secret")
    registrations = {}
    observed = set()

    def provider_respond(request):
        assert request.headers["authorization"] == "Bearer provider-secret"
        if request.method == "POST":
            nonce = json.loads(request.content)["nonce"]
            identifier = f"registration_{len(registrations) + 1}"
            registrations[identifier] = nonce
            return httpx.Response(
                201,
                json={
                    "registration_id": identifier,
                    "callback_url": f"https://callback.example/{identifier}",
                },
            )
        identifier = request.url.path.split("/")[2]
        events = (
            [{"registration_id": identifier, "nonce": registrations[identifier]}]
            if identifier in observed
            else []
        )
        return httpx.Response(200, json={"events": events})

    def target_respond(request):
        callback = request.url.params.get("url", "")
        observed.add(urlsplit(callback).path.strip("/"))
        return httpx.Response(200, text="queued")

    budget = ExecutionBudget(max_requests=8, requests_per_second_per_host=1000)
    contract = SSRFContract(
        probe_url="https://example.com/fetch?url=about:blank",
        parameter="url",
        provider_url="https://provider.example",
        provider_token_env="OAST_TOKEN",
    )
    async with (
        httpx.AsyncClient(
            transport=httpx.MockTransport(provider_respond)
        ) as provider_client,
        httpx.AsyncClient(
            transport=httpx.MockTransport(target_respond)
        ) as target_client,
    ):
        result = await prove_ssrf(
            contract,
            budget,
            provider_client=provider_client,
            target_client=target_client,
        )
    assert result["validated"] is True
    assert budget.snapshot()["requests_used"] == 8
    assert "provider-secret" not in str(result)
    assert "callback.example" not in str(result)


@pytest.mark.asyncio
async def test_oast_provider_cannot_return_cloud_metadata_callback(monkeypatch):
    monkeypatch.setenv("OAST_PROVIDER_DOMAINS", "provider.example")
    monkeypatch.setenv("OAST_CALLBACK_DOMAINS", "callback.example")

    def respond(request):
        return httpx.Response(
            201,
            json={
                "registration_id": "registration_1",
                "callback_url": "http://169.254.169.254/latest/meta-data/",
            },
        )

    budget = ExecutionBudget(max_requests=2)
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        provider = OASTClient(
            "https://provider.example",
            token="fixture-token",
            budget=budget,
            client=client,
        )
        with pytest.raises(RuntimeError, match="unapproved registration"):
            await provider.register()
    assert provider.callback_url is None
    assert budget.snapshot()["requests_used"] == 1
