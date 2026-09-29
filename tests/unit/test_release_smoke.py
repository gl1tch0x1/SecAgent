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
