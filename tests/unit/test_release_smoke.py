import argparse
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.release_smoke import run_release_smoke_check, validate_release_artifact


def test_installer_requires_operator_scope_and_cli_scope_command_works(
    tmp_path: Path, monkeypatch
):
    import installer
    from secagents.cli import build_parser, cmd_scope

    env_file = tmp_path / ".env"
    monkeypatch.setattr(installer, "ENV_FILE", env_file)
    assert installer.configure_intel(argparse.Namespace(allowed_domains=None))
    assert "ALLOWED_DOMAINS=" not in env_file.read_text(encoding="utf-8")
    scope_args = build_parser().parse_args(
        ["scope", "--add", "app.example", "--env", str(env_file)]
    )
    assert cmd_scope(scope_args) == 0
    assert "ALLOWED_DOMAINS=app.example" in env_file.read_text(encoding="utf-8")
    assert (
        build_parser().parse_args(["scan", "-t", "app.example"]).target == "app.example"
    )


def test_scope_imports_domain_lists_atomically(tmp_path: Path, monkeypatch):
    from secagents.cli import build_parser, cmd_scope

    env_path = tmp_path / ".env"
    source = tmp_path / "domains.txt"
    source.write_text(
        "# approved targets\napp.example\napi.example,*.services.example\n",
        encoding="utf-8",
    )
    args = build_parser().parse_args(
        [
            "scope",
            "--add",
            "other.example",
            "--file",
            str(source),
            "--env",
            str(env_path),
        ]
    )
    assert cmd_scope(args) == 0
    assert env_path.read_text(encoding="utf-8").strip() == (
        "ALLOWED_DOMAINS=other.example,app.example,api.example,*.services.example"
    )
    source.write_text("valid.example\nhttps://invalid.example\n", encoding="utf-8")
    before = env_path.read_bytes()
    assert cmd_scope(args) == 2
    assert env_path.read_bytes() == before


@pytest.mark.asyncio
async def test_batch_scan_authorizes_explicit_list_but_respects_blocks(
    tmp_path: Path, monkeypatch
):
    from secagents import cli

    source = tmp_path / "targets.txt"
    source.write_text("app.example\napi.example\n", encoding="utf-8")
    monkeypatch.delenv("ALLOWED_DOMAINS", raising=False)
    monkeypatch.delenv("BLOCKED_DOMAINS", raising=False)
    seen = []

    async def fake_scan(args):
        seen.append(args.target)
        return 0

    monkeypatch.setattr(cli, "cmd_scan", fake_scan)
    args = cli.build_parser().parse_args(
        ["scan", "--targets-file", str(source), "--authorize-targets"]
    )
    assert await cli.cmd_scan_batch(args) == 0
    assert seen == ["app.example", "api.example"]
    assert cli.enforce_scope("api.example") == "api.example"
    from secagents.config import load_runtime_config

    single = cli.build_parser().parse_args(["scan", "-t", "app.example"])
    assert load_runtime_config(single).scan.target == "app.example"

    monkeypatch.setenv("BLOCKED_DOMAINS", "api.example")
    seen.clear()
    assert await cli.cmd_scan_batch(args) == 2
    assert not seen


def test_installer_clears_live_display_before_final_commands(monkeypatch):
    import installer

    class FakeLive:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def update(self, *args):
            pass

    class FakeConsole:
        is_terminal = True

        def clear(self):
            calls.append("clear")

    calls = []
    monkeypatch.setattr(installer, "Live", FakeLive)
    monkeypatch.setattr(installer, "console", FakeConsole())
    monkeypatch.setattr(installer, "run_preflight", lambda args: True)
    monkeypatch.setattr(installer, "deploy_environment", lambda: True)
    monkeypatch.setattr(installer, "install_arsenal", lambda args: True)
    monkeypatch.setattr(installer, "configure_intel", lambda args: True)
    monkeypatch.setattr(installer, "create_entrypoints", lambda: True)
    monkeypatch.setattr(
        installer, "print_final_report", lambda *args, **kwargs: calls.append("final")
    )
    monkeypatch.setattr(installer.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(sys, "argv", ["installer.py", "--no-test"])

    assert installer.main() == 0
    assert calls == ["clear", "final"]


def test_validate_release_artifact_requires_help_and_version_proof(tmp_path: Path):
    fake_bin = tmp_path / (
        "fake-secagent.py" if sys.platform == "win32" else "fake-secagent"
    )
    fake_bin.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "if '--version' in sys.argv:\n"
        "    print('SecAgent 1.0.0')\n"
        "    sys.exit(0)\n"
        "print('SecAgent 1.0.0')\n"
        "print('usage: fake-secagent [--help] [scan --target TARGET]')\n"
        "sys.exit(0)\n"
    )
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)

    proof = validate_release_artifact(
        str(fake_bin), timeout=10, expected_version="1.0.0"
    )

    assert proof.return_code == 0
    assert proof.version == "1.0.0"
    assert proof.help_text is not None
    assert "usage" in proof.help_text.lower()


def test_validate_release_artifact_rejects_version_mismatch(tmp_path: Path):
    fake_bin = tmp_path / (
        "fake-secagent.py" if sys.platform == "win32" else "fake-secagent"
    )
    fake_bin.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "if '--version' in sys.argv:\n"
        "    print('SecAgent 1.0.0')\n"
        "    sys.exit(0)\n"
        "print('usage: fake-secagent [--help]')\n"
        "sys.exit(0)\n"
    )
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)

    with pytest.raises(ValueError, match="version mismatch"):
        validate_release_artifact(str(fake_bin), timeout=10, expected_version="2.0.0")


def test_run_release_smoke_check_accepts_help_output(tmp_path: Path):
    fake_bin = tmp_path / (
        "fake-secagent.py" if sys.platform == "win32" else "fake-secagent"
    )
    fake_bin.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('SecAgent 1.0.0')\n"
        "print('usage: fake-secagent [--help] [scan --target TARGET]')\n"
        "sys.exit(0)\n"
    )
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)

    completed = run_release_smoke_check(str(fake_bin), ["--help"], timeout=10)

    assert completed.returncode == 0
    assert "SecAgent" in completed.stdout
    assert "usage" in completed.stdout.lower()


def test_run_release_smoke_check_rejects_nonzero_exit(tmp_path: Path):
    fake_bin = tmp_path / (
        "bad-secagent.py" if sys.platform == "win32" else "bad-secagent"
    )
    fake_bin.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('startup failed', file=sys.stderr)\n"
        "sys.exit(2)\n"
    )
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)

    completed = run_release_smoke_check(str(fake_bin), ["--help"], timeout=10)

    assert completed.returncode == 2
    assert "startup failed" in completed.stderr.lower()


def test_updater_refuses_dirty_tree_without_merging(monkeypatch):
    import update

    calls = []
    monkeypatch.setattr(update, "_banner", lambda: None)
    monkeypatch.setattr(update, "_display", lambda *args, **kwargs: None)
    monkeypatch.setattr(update, "_check_repository", lambda: None)
    monkeypatch.setattr(update, "_fetch", lambda: ("a" * 40, "b" * 40))
    monkeypatch.setattr(update, "_git_output", lambda *args: "1")
    monkeypatch.setattr(update, "_working_tree_clean", lambda: False)

    def fake_git(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(
            args,
            1 if args[:3] == ("merge-base", "--is-ancestor", "b" * 40) else 0,
            "",
            "",
        )

    monkeypatch.setattr(update, "_git", fake_git)
    assert update.main([]) == 1
    assert not any(args[0] == "merge" for args in calls)


def test_updater_check_only_and_fast_forward_install(monkeypatch):
    import update

    calls = []
    monkeypatch.setattr(update, "_banner", lambda: None)
    monkeypatch.setattr(update, "_display", lambda *args, **kwargs: None)
    monkeypatch.setattr(update, "_check_repository", lambda: None)
    monkeypatch.setattr(update, "_fetch", lambda: ("a" * 40, "b" * 40))
    monkeypatch.setattr(update, "_git_output", lambda *args: "1")
    monkeypatch.setattr(update, "_working_tree_clean", lambda: True)
    monkeypatch.setattr(
        update, "_install", lambda domains: calls.append(("install", domains))
    )

    def fake_git(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(
            args,
            1 if args[:3] == ("merge-base", "--is-ancestor", "b" * 40) else 0,
            "",
            "",
        )

    monkeypatch.setattr(update, "_git", fake_git)
    assert update.main(["--check-only"]) == 0
    assert not any(args[0] in {"merge", "install"} for args in calls)
    assert update.main(["--allowed-domains", "app.example"]) == 0
    assert ("merge", "--ff-only", "b" * 40) in calls
    assert ("install", "app.example") in calls


def test_updater_propagates_installer_failure(monkeypatch):
    import update

    monkeypatch.setattr(update, "_banner", lambda: None)
    monkeypatch.setattr(update, "_display", lambda *args, **kwargs: None)
    monkeypatch.setattr(update, "_check_repository", lambda: None)
    monkeypatch.setattr(update, "_fetch", lambda: ("a" * 40, "b" * 40))
    monkeypatch.setattr(update, "_git_output", lambda *args: "1")
    monkeypatch.setattr(update, "_working_tree_clean", lambda: True)
    monkeypatch.setattr(
        update,
        "_git",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args,
            1 if args[:3] == ("merge-base", "--is-ancestor", "b" * 40) else 0,
            "",
            "",
        ),
    )
    monkeypatch.setattr(
        update,
        "_install",
        lambda domains: (_ for _ in ()).throw(RuntimeError("install failed")),
    )
    assert update.main([]) == 1


def test_updater_treats_local_ahead_as_no_inbound_update(monkeypatch):
    import update

    calls = []
    monkeypatch.setattr(update, "_banner", lambda: None)
    monkeypatch.setattr(update, "_display", lambda *args, **kwargs: None)
    monkeypatch.setattr(update, "_check_repository", lambda: None)
    monkeypatch.setattr(update, "_fetch", lambda: ("a" * 40, "b" * 40))

    def fake_git(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(update, "_git", fake_git)
    assert update.main([]) == 0
    assert not any(args[0] == "merge" for args in calls)


@pytest.mark.asyncio
async def test_health_endpoint_reports_degraded_without_inventing_readiness(
    monkeypatch,
):
    from secagents.infra import health_checks

    async def degraded():
        return {"status": health_checks.HealthStatus.DEGRADED, "services": {}}

    monkeypatch.setattr(health_checks.health_check, "run_all_checks", degraded)
    response = await health_checks.health()
    assert response.status_code == 200
    assert b'"status":"degraded"' in response.body


def test_deployment_image_paths_exist_and_compose_has_api():
    import yaml

    root = Path(__file__).resolve().parents[2]
    compose = yaml.safe_load((root / "docker-compose.yml").read_text(encoding="utf-8"))
    dockerfile = compose["services"]["api"]["build"]["dockerfile"]
    assert (root / dockerfile).is_file()
    workflow = (root / ".github/workflows/cd.yml").read_text(encoding="utf-8")
    assert f"file: {dockerfile}" in workflow
    assert "docker compose exec -T postgres" not in workflow


def test_installer_llm_skip_preserves_existing_configuration(tmp_path, monkeypatch):
    import installer

    env_path = tmp_path / ".env"
    env_path.write_text("OPENAI_API_KEY=existing-secret\n", encoding="utf-8")
    monkeypatch.setattr(installer, "ENV_FILE", env_path)
    monkeypatch.setattr("builtins.input", lambda _: "Skip")
    assert installer.configure_llm_interactive()
    assert env_path.read_text(encoding="utf-8") == "OPENAI_API_KEY=existing-secret\n"


def test_installer_saves_explicit_deepseek_provider_without_echoing_key(
    tmp_path, monkeypatch, capsys
):
    import installer

    env_path = tmp_path / ".env"
    env_path.write_text("JWT_SECRET=keep-me\n", encoding="utf-8")
    monkeypatch.setattr(installer, "ENV_FILE", env_path)
    answers = iter(["Yes", "3", "deepseek-flash"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(installer.getpass, "getpass", lambda _: "sk-deepseek-private")
    assert installer.configure_llm_interactive()
    content = env_path.read_text(encoding="utf-8")
    assert "SECAGENT_LLM_PROVIDER=deepseek" in content
    assert "SECAGENT_LLM_MODEL=deepseek-flash" in content
    assert "DEEPSEEK_API_KEY=sk-deepseek-private" in content
    assert "JWT_SECRET=keep-me" in content
    assert "sk-deepseek-private" not in capsys.readouterr().out


def test_installer_custom_route_requires_secure_full_endpoint(tmp_path, monkeypatch):
    import installer

    env_path = tmp_path / ".env"
    monkeypatch.setattr(installer, "ENV_FILE", env_path)
    answers = iter(
        [
            "Yes",
            "6",
            "my-gateway",
            "my-model",
            "http://remote.example/v1/chat/completions",
            "https://gateway.example/v1/chat/completions",
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(installer.getpass, "getpass", lambda _: "gateway-secret")
    assert installer.configure_llm_interactive()
    content = env_path.read_text(encoding="utf-8")
    assert "SECAGENT_LLM_PROVIDER=custom" in content
    assert "SECAGENT_LLM_NAME=my-gateway" in content
    assert (
        "SECAGENT_LLM_ENDPOINT=https://gateway.example/v1/chat/completions" in content
    )
    assert "SECAGENT_LLM_API_KEY=gateway-secret" in content


def test_cli_reads_selected_env_file_outside_project(tmp_path, monkeypatch):
    from secagents import cli

    env_path = tmp_path / ".env"
    env_path.write_text(
        "SECAGENT_LLM_PROVIDER=google\nGEMINI_API_KEY=example-test-key\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SECAGENT_ENV_FILE", str(env_path))
    monkeypatch.delenv("SECAGENT_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    cli._load_env()
    assert cli.os.environ["SECAGENT_LLM_PROVIDER"] == "google"
    assert cli.os.environ["GEMINI_API_KEY"] == "example-test-key"


def test_custom_llm_rejects_remote_cleartext_route(monkeypatch):
    from secagents.llm.omni import OmniLLM

    monkeypatch.setenv("SECAGENT_LLM_PROVIDER", "custom")
    monkeypatch.setenv("SECAGENT_LLM_MODEL", "custom-model")
    monkeypatch.setenv("SECAGENT_LLM_API_KEY", "example-test-key")
    monkeypatch.setenv(
        "SECAGENT_LLM_ENDPOINT", "http://remote.example/v1/chat/completions"
    )
    with pytest.raises(ValueError, match="HTTPS"):
        OmniLLM()


@pytest.mark.asyncio
async def test_vault_identifies_deepseek_by_env_name_not_key_prefix(
    tmp_path, monkeypatch
):
    from secagents.vault.env_loader import Vault

    vault = Vault(tmp_path / ".env")
    seen = []

    async def fake_validate(provider, key):
        seen.append((provider, key))
        return True, "ok"

    monkeypatch.setattr(vault, "_cheap_validation", fake_validate)
    report = await vault._probe_key("DEEPSEEK_API_KEY", "sk-shared-prefix")
    assert report.status.value == "valid"
    assert seen == [("deepseek", "sk-shared-prefix")]


@pytest.mark.asyncio
async def test_llm_deepseek_key_uses_deepseek_route_not_openai(monkeypatch):
    import json
    import httpx
    from secagents.llm.omni import LLMMessage, OmniLLM

    monkeypatch.setenv("SECAGENT_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("SECAGENT_LLM_MODEL", "deepseek-flash")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-not-an-openai-key")
    requests = []

    def responder(request):
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    async with OmniLLM() as llm:
        await llm._client.aclose()
        llm._client = httpx.AsyncClient(transport=httpx.MockTransport(responder))
        response = await llm.complete([LLMMessage("user", "test")])
    assert response.provider == "deepseek"
    assert requests[0].url == "https://api.deepseek.com/chat/completions"
    assert requests[0].headers["authorization"] == "Bearer sk-not-an-openai-key"
    deepseek_body = json.loads(requests[0].read())
    assert deepseek_body["model"] == "deepseek-flash"
    assert deepseek_body["max_tokens"] == 2048


@pytest.mark.asyncio
async def test_llm_custom_route_and_gemini_header(monkeypatch):
    import httpx
    from secagents.llm.omni import LLMMessage, OmniLLM

    monkeypatch.setenv("SECAGENT_LLM_PROVIDER", "custom")
    monkeypatch.setenv("SECAGENT_LLM_MODEL", "custom-model")
    monkeypatch.setenv("SECAGENT_LLM_API_KEY", "custom-secret")
    monkeypatch.setenv(
        "SECAGENT_LLM_ENDPOINT", "https://gateway.example/v2/chat/completions"
    )
    monkeypatch.setenv("SECAGENT_LLM_NAME", "my-gateway")
    requests = []

    def custom_responder(request):
        requests.append(request)
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "custom-ok"}}]}
        )

    async with OmniLLM() as llm:
        await llm._client.aclose()
        llm._client = httpx.AsyncClient(transport=httpx.MockTransport(custom_responder))
        result = await llm.complete([LLMMessage("user", "test")])
        assert result.content == "custom-ok"
        assert result.provider == "my-gateway"
    assert requests[0].url == "https://gateway.example/v2/chat/completions"

    monkeypatch.setenv("SECAGENT_LLM_PROVIDER", "google")
    monkeypatch.setenv("SECAGENT_LLM_MODEL", "gemini-3.8-flash")
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-secret")
    requests.clear()

    def gemini_responder(request):
        requests.append(request)
        return httpx.Response(
            200, json={"candidates": [{"content": {"parts": [{"text": "gemini-ok"}]}}]}
        )

    async with OmniLLM() as llm:
        await llm._client.aclose()
        llm._client = httpx.AsyncClient(transport=httpx.MockTransport(gemini_responder))
        assert (await llm.complete([LLMMessage("user", "test")])).content == "gemini-ok"
    assert "key=" not in str(requests[0].url)
    assert requests[0].headers["x-goog-api-key"] == "gemini-secret"


@pytest.mark.asyncio
async def test_llm_openai_and_claude_use_their_own_auth_and_routes(monkeypatch):
    import json
    import httpx
    from secagents.llm.omni import LLMMessage, OmniLLM

    requests = []

    def responder(request):
        requests.append(request)
        if request.url.host == "api.anthropic.com":
            return httpx.Response(200, json={"content": [{"text": "claude-ok"}]})
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "openai-ok"}}]}
        )

    monkeypatch.setenv("SECAGENT_LLM_PROVIDER", "openai")
    monkeypatch.setenv("SECAGENT_LLM_MODEL", "gpt-4o-mini")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-secret")
    async with OmniLLM() as llm:
        await llm._client.aclose()
        llm._client = httpx.AsyncClient(transport=httpx.MockTransport(responder))
        assert (await llm.complete([LLMMessage("user", "test")])).content == "openai-ok"
    assert requests[0].url == "https://api.openai.com/v1/chat/completions"
    assert requests[0].headers["authorization"] == "Bearer openai-secret"
    assert json.loads(requests[0].read())["max_completion_tokens"] == 2048

    monkeypatch.setenv("SECAGENT_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("SECAGENT_LLM_MODEL", "claude-sonnet-5")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "claude-secret")
    async with OmniLLM() as llm:
        await llm._client.aclose()
        llm._client = httpx.AsyncClient(transport=httpx.MockTransport(responder))
        assert (await llm.complete([LLMMessage("user", "test")])).content == "claude-ok"
    assert requests[1].url == "https://api.anthropic.com/v1/messages"
    assert requests[1].headers["x-api-key"] == "claude-secret"


@pytest.mark.asyncio
async def test_llm_ollama_uses_local_host_without_a_cloud_key(monkeypatch):
    import httpx
    from secagents.llm.omni import LLMMessage, OmniLLM

    monkeypatch.setenv("SECAGENT_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("SECAGENT_LLM_MODEL", "llama3.2:3b")
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
    monkeypatch.delenv("SECAGENT_LLM_API_KEY", raising=False)
    requests = []

    def responder(request):
        requests.append(request)
        return httpx.Response(200, json={"message": {"content": "local-ok"}})

    async with OmniLLM() as llm:
        await llm._client.aclose()
        llm._client = httpx.AsyncClient(transport=httpx.MockTransport(responder))
        assert (await llm.complete([LLMMessage("user", "test")])).content == "local-ok"
    assert requests[0].url == "http://localhost:11434/api/chat"
    assert "authorization" not in requests[0].headers


def test_installer_reuses_saved_llm_key_and_ignores_placeholders(tmp_path, monkeypatch):
    import installer

    env_path = tmp_path / ".env"
    monkeypatch.setattr(installer, "ENV_FILE", env_path)
    env_path.write_text(
        "SECAGENT_LLM_PROVIDER=deepseek\nDEEPSEEK_API_KEY=sk-real-test-key\n",
        encoding="utf-8",
    )
    assert installer._saved_llm_provider() == "deepseek"
    env_path.write_text("OPENAI_API_KEY=sk-...\n", encoding="utf-8")
    assert installer._saved_llm_provider() is None


def test_reinstall_with_saved_llm_does_not_ask_for_key(tmp_path, monkeypatch):
    import installer

    class FakeLive:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def update(self, *args):
            pass

    class FakeConsole:
        is_terminal = False

        def print(self, *args, **kwargs):
            pass

    env_path = tmp_path / ".env"
    env_path.write_text(
        "SECAGENT_LLM_PROVIDER=deepseek\nDEEPSEEK_API_KEY=sk-saved-test-key\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(installer, "ENV_FILE", env_path)
    monkeypatch.setattr(installer, "Live", FakeLive)
    monkeypatch.setattr(installer, "console", FakeConsole())
    monkeypatch.setattr(
        installer.sys, "stdin", type("TTY", (), {"isatty": lambda self: True})()
    )
    monkeypatch.setattr(installer.sys, "argv", ["installer.py", "--no-test"])
    for name in (
        "run_preflight",
        "deploy_environment",
        "install_arsenal",
        "configure_intel",
        "create_entrypoints",
    ):
        monkeypatch.setattr(installer, name, lambda *args: True)
    monkeypatch.setattr(installer, "print_final_report", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        installer,
        "configure_llm_interactive",
        lambda: pytest.fail("Prompted for a saved key"),
    )
    assert installer.main() == 0


@pytest.mark.parametrize("terminal_width", [72, 100, 160])
def test_installer_live_layout_is_bounded_and_preserves_banner(
    terminal_width, monkeypatch
):
    import io

    import installer
    from rich.console import Console

    output = io.StringIO()
    monkeypatch.setattr(
        installer,
        "console",
        Console(file=output, force_terminal=False, width=terminal_width),
    )
    display = installer.DeploymentUI()
    for name in ("PREFLIGHT", "ENVIRONMENT", "ARSENAL", "SCOPE"):
        display.add_phase(name)
    display.update_phase(0, "success")
    display.update_phase(1, "active")
    display.active_phase = "ENVIRONMENT"
    display.update_log("Virtual environment is ready.", "success")
    installer.console.print(display.render())
    rendered = output.getvalue()
    assert "_____           ___                    __" in (
        rendered if terminal_width >= 76 else installer.BANNER
    )
    assert "ENVIRONMENT" in rendered
    assert "Virtual environment is ready." in rendered
    assert all(len(line) <= terminal_width for line in rendered.splitlines())


def test_installer_completion_shows_verified_commands_without_api_key(
    tmp_path, monkeypatch
):
    import io

    import installer
    from rich.console import Console

    output = io.StringIO()
    env_file = tmp_path / ".env"
    env_file.write_text(
        "ALLOWED_DOMAINS=app.example\nOPENAI_API_KEY=private-test-key\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(installer, "ENV_FILE", env_file)
    monkeypatch.setattr(
        installer,
        "console",
        Console(
            file=output,
            force_terminal=False,
            width=100,
            theme=installer.custom_theme,
        ),
    )
    display = installer.DeploymentUI()
    display.add_phase("PREFLIGHT", "success")
    display.add_phase("INTEGRITY", "success")
    display.update_log("CLI command verified.", "success")
    monkeypatch.setattr(installer, "ui", display)

    installer.print_final_report(True)
    rendered = output.getvalue()
    assert "INSTALL COMPLETE" in rendered
    assert "DEPLOYMENT SUMMARY" in rendered
    assert "FIRST COMMANDS" in rendered
    assert "app.example" in rendered
    assert "private-test-key" not in rendered


def test_role_prompts_include_new_hunting_skills_without_full_global_guide():
    from secagents.core.skill_manager import skill_manager

    names = skill_manager.available_skills()
    assert {
        "HuntPlanning",
        "APIAssessment",
        "BusinessLogic",
        "EvidenceValidation",
    } <= set(names)
    api_prompt = skill_manager.apply_to_prompt("Base", "api_security")
    assert "API Assessment" in api_prompt
    assert "state read" in api_prompt
    assert len(api_prompt) < 6000
    assert skill_manager.get_skill("apiassessment") == skill_manager.get_skill(
        "APIAssessment"
    )


@pytest.mark.asyncio
async def test_hunt_plan_uses_scope_and_selected_skill_without_live_target_requests(
    monkeypatch, capsys
):
    import json
    from secagents import cli
    from secagents.llm import omni

    monkeypatch.setenv("ALLOWED_DOMAINS", "app.example")
    monkeypatch.delenv("BLOCKED_DOMAINS", raising=False)
    captured = []

    class FakeLLM:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def complete(self, messages, **kwargs):
            captured.extend(messages)
            return omni.LLMResponse(
                content=json.dumps({"hypotheses": [], "scope": ["app.example"]}),
                provider="test",
                model="test-model",
            )

    monkeypatch.setattr(omni, "OmniLLM", FakeLLM)
    args = cli.build_parser().parse_args(
        ["hunt-plan", "-t", "app.example", "--focus", "api", "--request-budget", "10"]
    )
    assert await cli.cmd_hunt_plan(args) == 0
    assert "API Assessment" in captured[0].content
    assert "10" in captured[1].content
    assert "hypotheses" in capsys.readouterr().out

    captured.clear()
    args.target = "outside.example"
    assert await cli.cmd_hunt_plan(args) == 2
    assert captured == []
