"""Unit test suite for SecAgent Next-Gen Enhancements (MCP, Playbooks, Capsules, Teleoperation, Budget Guard)."""

import json
import time
from pathlib import Path

import pytest
from secagents.infra.budget_guard import BudgetGuard
from secagents.infra.teleoperation import TeleoperationController
from secagents.mcp_server import MCPServer
from secagents.operational.playbook import Playbook, PlaybookPhase, PlaybookRunner
from secagents.operational.proof_capsule import ProofCapsule, ProofCapsuleReplayer


def test_proof_capsule_serialization(tmp_path: Path):
    capsule = ProofCapsule(
        id="cap-123",
        target_url="https://example.com/search",
        vuln_type="sqli",
        title="SQL Injection on query param",
        severity="critical",
        http_method="GET",
        request_headers={"User-Agent": "SecAgent"},
        request_body=None,
        query_params={"q": "' OR '1'='1"},
        proof_signal="SQL syntax error",
        timestamp=time.time(),
        metadata={"cwe": "CWE-89"},
    )

    cap_file = tmp_path / "capsule.json"
    capsule.save(cap_file)

    loaded = ProofCapsule.from_json(cap_file.read_text(encoding="utf-8"))
    assert loaded.id == "cap-123"
    assert loaded.vuln_type == "sqli"
    assert loaded.proof_signal == "SQL syntax error"


@pytest.mark.asyncio
async def test_proof_capsule_replay_async(monkeypatch):
    import httpx
    from secagents.operational import proof_capsule

    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    original_client = httpx.AsyncClient
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="OK"))
    monkeypatch.setattr(proof_capsule.httpx, "AsyncClient", lambda **kwargs: original_client(transport=transport))
    capsule = ProofCapsule(
        id="cap-test",
        target_url="https://example.com",
        vuln_type="test",
        title="Test Proof Signal",
        severity="info",
        http_method="GET",
        request_headers={},
        request_body=None,
        query_params={},
        proof_signal="Example Domain",
        timestamp=time.time(),
        metadata={"check_key": "missing_headers"},
    )
    replayer = ProofCapsuleReplayer(timeout_seconds=5.0)
    ok, msg = await replayer.replay_async(capsule)
    assert ok is True
    assert "[VERIFIED]" in msg


def test_budget_guard():
    guard = BudgetGuard(limit_usd=0.01)
    assert guard.is_budget_exceeded() is False

    # Record usage
    guard.record_usage(prompt_tokens=5000, completion_tokens=2000, provider="openai")
    assert guard.total_prompt_tokens == 5000
    assert guard.total_completion_tokens == 2000
    assert guard.total_cost_usd > 0
    assert guard.is_budget_exceeded() is True

    summary = guard.summary()
    assert summary["exceeded"] is True


def test_teleoperation_controller():
    ctrl = TeleoperationController()
    assert ctrl.is_paused is False
    ctrl.enable()
    assert ctrl._previous_handler is not None
    ctrl.disable()


def test_playbook_parsing_and_execution():
    pb = Playbook(
        name="Unit Test Playbook",
        phases=[
            PlaybookPhase(id="recon", tools=["nmap", "httpx"]),
            PlaybookPhase(id="vuln_scan", tools=["nuclei"], depends_on=["recon"]),
        ],
    )
    runner = PlaybookRunner(pb)
    res = runner.run("example.com")
    assert res is True
    assert "recon" in runner.completed_phases
    assert "vuln_scan" in runner.completed_phases


def test_mcp_server_jsonrpc():
    server = MCPServer()

    # 1. tools/list
    req_list = json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 1})
    resp_list = json.loads(server.process_request(req_list))
    assert "result" in resp_list
    assert len(resp_list["result"]["tools"]) == 4

    # 2. tools/call -> secagent_list_tools
    req_call = json.dumps({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "secagent_list_tools", "arguments": {}}, "id": 2})
    resp_call = json.loads(server.process_request(req_call))
    assert "result" in resp_call
    content_text = json.loads(resp_call["result"]["content"][0]["text"])
    assert "tools" in content_text
