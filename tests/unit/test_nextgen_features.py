"""Unit test suite for SecAgent Next-Gen Enhancements (MCP, Playbooks, Capsules, Teleoperation, Budget Guard)."""

import json
import io
import sqlite3
import sys
import time
from pathlib import Path

import pytest
from secagents.infra.budget_guard import BudgetGuard
from secagents.infra.teleoperation import TeleoperationController
from secagents.mcp_server import MCPServer
from secagents.operational.playbook import Playbook, PlaybookPhase, PlaybookRunner
from secagents.operational.proof_capsule import ProofCapsule, ProofCapsuleReplayer
from secagents.operational.fuzzing import (
    BinaryFuzzConfig,
    byte_changes,
    payload_variants,
    run_binary_fuzz,
    _run_program,
)
from secagents.core.aura_memory import AuraMemoryManager


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


def test_binary_fuzzer_tracks_input_and_output_bits_and_skips_repeats(tmp_path: Path):
    seed = tmp_path / "sample.bin"
    seed.write_bytes(b"\x10\x20\x30")
    memory = AuraMemoryManager(db_path=tmp_path / "aura.db")
    config = BinaryFuzzConfig(
        seed_path=seed,
        results_dir=tmp_path / "results",
        program=Path(sys.executable),
        program_args=(
            "-c",
            "import pathlib,sys; b=pathlib.Path(sys.argv[1]).read_bytes(); "
            "sys.stdout.buffer.write(bytes([sum(b)%256]))",
            "{input}",
        ),
        allow_host_execution=True,
        runs=6,
        timeout_seconds=3,
        max_duration_seconds=30,
        max_saved_cases=2,
    )
    first = run_binary_fuzz(config, memory)
    assert first["summary"]["cases_executed"] == 6
    assert first["summary"]["outcomes_changed"] > 0
    assert first["summary"]["saved_cases"] <= 2
    assert any(case["input_bit_diff"]["changes"] for case in first["cases"])
    assert any(case["stdout_bit_diff"]["changes"] for case in first["cases"])
    assert Path(first["report_path"]).exists()
    with sqlite3.connect(tmp_path / "aura.db") as conn:
        assert (
            conn.execute("SELECT SUM(attempts) FROM fuzz_operator_feedback").fetchone()[
                0
            ]
            == 6
        )

    second = run_binary_fuzz(config, memory)
    assert second["summary"]["cases_executed"] == 6
    assert second["summary"]["skipped_repeated_inputs"] >= 6
    assert not (
        {case["input_sha256"] for case in first["cases"]}
        & {case["input_sha256"] for case in second["cases"]}
    )


def test_binary_bit_positions_and_payload_variant_limits():
    diff = byte_changes(b"\x00", b"\x81")
    assert diff["changes"][0]["changed_bit_offsets"] == [0, 7]
    base = {"method": "GET", "param": "q", "value": "1 OR 1=1--"}
    variants = payload_variants("sqli", base, 3)
    assert len(variants) == 3
    assert len({item["value"] for item in variants}) == 3
    combined = payload_variants("sqli", base, 32)
    assert any("+" in item["mutation_name"] for item in combined)
    assert len(combined) <= 32
    assert len({item["value"] for item in combined}) == len(combined)
    assert payload_variants("sqli", base, 0) == []
    with pytest.raises(ValueError):
        BinaryFuzzConfig(
            seed_path=Path("input.bin"),
            results_dir=Path("results"),
            program=Path(sys.executable),
        )


def test_binary_fuzzer_bounds_output_capture_and_program_time(tmp_path: Path):
    seed = tmp_path / "sample.bin"
    seed.write_bytes(b"\x00")
    memory = AuraMemoryManager(db_path=tmp_path / "aura.db")
    config = BinaryFuzzConfig(
        seed_path=seed,
        results_dir=tmp_path / "results",
        program=Path(sys.executable),
        program_args=(
            "-c",
            "import sys; sys.stdout.buffer.write(b'x'*100000); sys.stdout.flush()",
            "{input}",
        ),
        allow_host_execution=True,
        runs=1,
        timeout_seconds=2,
        max_output_bytes=16,
        max_duration_seconds=5,
    )
    report = run_binary_fuzz(config, memory)
    assert report["baseline"]["stdout"]["size"] == 100000
    assert report["baseline"]["stdout"]["truncated"] is True
    assert (
        report["cases"][0]["outcome"]["stdout"]["sha256"]
        == report["baseline"]["stdout"]["sha256"]
    )


def test_binary_fuzzer_uses_instrumented_coverage_and_minimizes_crash(tmp_path: Path):
    seed = tmp_path / "sample.bin"
    seed.write_bytes(b"ABCD")
    memory = AuraMemoryManager(db_path=tmp_path / "aura.db")
    script = (
        "import os,pathlib,sys; "
        "data=pathlib.Path(sys.argv[1]).read_bytes(); "
        "pathlib.Path(os.environ['SECAGENT_COVERAGE_FILE']).write_bytes(bytes([sum(data)%256])); "
        "sys.stderr.write('AddressSanitizer: synthetic fixture\\n') if data != b'ABCD' else None; "
        "sys.exit(77 if data != b'ABCD' else 0)"
    )
    config = BinaryFuzzConfig(
        seed_path=seed,
        results_dir=tmp_path / "results",
        program=Path(sys.executable),
        program_args=("-c", script, "{input}"),
        allow_host_execution=True,
        collect_coverage=True,
        minimize_crashes=True,
        runs=1,
        timeout_seconds=3,
        max_duration_seconds=20,
    )
    report = run_binary_fuzz(config, memory)
    assert report["summary"]["novel_coverage_states"] == 1
    assert report["summary"]["novel_crashes"] == 1
    assert report["summary"]["minimization_executions"] >= 1
    assert report["cases"][0]["outcome"]["sanitizer_signal"] == "AddressSanitizer"
    assert (
        Path(report["cases"][0]["minimized_input"]).stat().st_size < seed.stat().st_size
    )


def test_binary_docker_mode_requires_exclusive_execution_choice():
    with pytest.raises(ValueError, match="not both"):
        BinaryFuzzConfig(
            seed_path=Path("input.bin"),
            results_dir=Path("results"),
            program=Path(sys.executable),
            allow_host_execution=True,
            docker_image="python:3.11",
        )


def test_binary_docker_command_has_no_network_and_resource_limits(
    tmp_path: Path, monkeypatch
):
    import secagents.operational.fuzzing as fuzzing

    program = tmp_path / "parser"
    program.write_bytes(b"fixture")
    input_path = tmp_path / "input.bin"
    input_path.write_bytes(b"input")
    seen = []

    class FakeProcess:
        stdout = io.BytesIO(b"")
        stderr = io.BytesIO(b"")
        returncode = 0

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(
        fuzzing.subprocess,
        "Popen",
        lambda command, **kwargs: seen.append(command) or FakeProcess(),
    )
    config = BinaryFuzzConfig(
        seed_path=input_path,
        results_dir=tmp_path,
        program=program,
        docker_image="local/parser:latest",
    )
    _run_program(config, input_path, tmp_path, 1.0)
    command = seen[0]
    assert command[:2] == ["docker", "run"]
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--pull=never" in command
    assert "--cap-drop=ALL" in command
    assert "--memory=256m" in command


def test_fuzz_cli_binary_mutation_needs_no_scan_target(tmp_path: Path):
    from secagents.cli import build_parser, cmd_fuzz

    seed = tmp_path / "sample.bin"
    seed.write_bytes(b"ABC")
    args = build_parser().parse_args(
        [
            "fuzz",
            "binary",
            str(seed),
            "--runs",
            "2",
            "--results-dir",
            str(tmp_path / "fuzz-results"),
        ]
    )
    assert cmd_fuzz(args) == 0
    assert len(list((tmp_path / "fuzz-results").glob("binary-fuzz-*.json"))) == 1


def test_proof_capsule_serialization_redacts_session_credentials():
    capsule = ProofCapsule(
        id="cap-auth",
        target_url="https://example.com/search?token=private-query",
        vuln_type="sqli",
        title="Private fixture",
        severity="high",
        http_method="GET",
        request_headers={
            "Authorization": "Bearer private-header",
            "Accept": "text/html",
        },
        request_body=None,
        query_params={"session": "private-session"},
        proof_signal="SQL syntax error",
        timestamp=time.time(),
        metadata={"request_header_env": {"Authorization": "SECAGENT_TEST_TOKEN"}},
    )
    serialized = capsule.to_json()
    assert "private-header" not in serialized
    assert "private-query" not in serialized
    assert "private-session" not in serialized
    loaded = ProofCapsule.from_json(serialized)
    assert loaded.request_headers["Authorization"] == "[REDACTED]"
    assert loaded.request_headers["Accept"] == "text/html"


@pytest.mark.asyncio
async def test_proof_capsule_replay_async(monkeypatch):
    import httpx
    from secagents.operational import proof_capsule

    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    original_client = httpx.AsyncClient
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="OK"))
    monkeypatch.setattr(
        proof_capsule.httpx,
        "AsyncClient",
        lambda **kwargs: original_client(transport=transport),
    )
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
    req_call = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "secagent_list_tools", "arguments": {}},
            "id": 2,
        }
    )
    resp_call = json.loads(server.process_request(req_call))
    assert "result" in resp_call
    content_text = json.loads(resp_call["result"]["content"][0]["text"])
    assert "tools" in content_text
