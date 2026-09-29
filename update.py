#!/usr/bin/env python3
"""Check for and safely apply SecAgent source updates."""

from __future__ import annotations

import argparse
import os
from importlib.util import find_spec
import shutil
import subprocess
import sys
import time
from pathlib import Path


BANNER = r"""
      _____           ___                    __
     / ___/___  _____/   | ____ ____  ____  / /______
     \__ \/ _ \/ ___/ /| |/ __ `/ _ \/ __ \/ __/ ___/
    ___/ /  __/ /__/ ___ / /_/ /  __/ / / / /_(__  )
   /____/\___/\___/_/  |_\__, /\___/_/ /_/_/   \___/
                        /____/
"""

ROOT = Path(__file__).resolve().parent


def _clear_terminal() -> None:
    """Clear only an interactive terminal; leave redirected update logs intact."""
    if not sys.stdout.isatty():
        return
    if find_spec("rich") is not None:
        from rich.console import Console

        Console().clear()
    elif os.name != "nt":
        print("\033[2J\033[H", end="", flush=True)


def _display(message: str, *, level: str = "info") -> None:
    stamp = time.strftime("%H:%M:%S")
    if find_spec("rich") is None:
        print(f"{stamp}  {level.upper():7}  {message}")
        return
    from rich.console import Console
    from rich.text import Text

    colors = {"info": "cyan", "success": "green", "warning": "yellow", "error": "red"}
    Console().print(
        Text(stamp, style="dim"),
        Text(f"{level.upper():7}", style=colors.get(level, "cyan")),
        Text(message),
    )


def _banner() -> None:
    if find_spec("rich") is None:
        print(BANNER)
        print("[ SECAGENT // SECURE UPLINK ]")
        return
    from rich.align import Align
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.text import Text

    display = Console()
    header = (
        Group(
            Text(BANNER.strip("\n"), style="bold green"),
            Text("// SECURE UPLINK  ::  FAST-FORWARD ONLY //", style="bold cyan"),
        )
        if display.width >= 76
        else Text("SECAGENT  /  SECURE UPLINK", style="bold green")
    )
    display.print(
        Align.center(Panel(header, border_style="green", width=min(display.width, 78)))
    )


def _git(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _git_output(*args: str) -> str:
    result = _git(*args)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _working_tree_clean() -> bool:
    result = _git("status", "--porcelain", "--untracked-files=normal")
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Could not inspect working tree")
    return not result.stdout.strip()


def _check_repository() -> None:
    if shutil.which("git") is None:
        raise RuntimeError("Git is required to update this source checkout")
    if Path(_git_output("rev-parse", "--show-toplevel")).resolve() != ROOT:
        raise RuntimeError("Updater must run from its own Git checkout")
    if _git_output("branch", "--show-current") != "main":
        raise RuntimeError("Updater only advances the main branch")
    if _git("remote", "get-url", "origin").returncode:
        raise RuntimeError("The origin remote is not configured")


def _fetch() -> tuple[str, str]:
    result = _git("fetch", "--no-tags", "origin", "main", timeout=180)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Could not fetch origin/main")
    local = _git_output("rev-parse", "HEAD")
    remote = _git_output("rev-parse", "FETCH_HEAD")
    return local, remote


def _install(allowed_domains: str | None) -> None:
    installer = ROOT / "installer.py"
    if not installer.is_file():
        raise RuntimeError("installer.py is missing after the update")
    command = [sys.executable, str(installer)]
    if allowed_domains:
        command.extend(["--allowed-domains", allowed_domains])
    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode:
        raise RuntimeError(f"Installer failed with exit code {result.returncode}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Safely update the SecAgent main checkout"
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Fetch and report; do not modify the checkout",
    )
    parser.add_argument(
        "--reinstall",
        action="store_true",
        help="Run installer even when already current",
    )
    parser.add_argument(
        "--allowed-domains", help="Explicit authorized domains to pass to installer"
    )
    args = parser.parse_args(argv)
    _clear_terminal()
    _banner()
    try:
        _check_repository()
        _display("Checking origin/main for a newer revision")
        local, remote = _fetch()
        if local == remote:
            _display(f"Already current at {local[:12]}", level="success")
            if args.reinstall and not args.check_only:
                _display("Rearming the local installation")
                _install(args.allowed_domains)
                _display("Installation verified", level="success")
            return 0

        if _git("merge-base", "--is-ancestor", remote, local).returncode == 0:
            _display(
                "Local main contains commits not yet on origin/main; no inbound update",
                level="warning",
            )
            return 0

        if _git("merge-base", "--is-ancestor", local, remote).returncode:
            raise RuntimeError(
                "Local main diverged from origin/main; resolve it manually"
            )
        incoming = _git_output("rev-list", "--count", f"{local}..{remote}")
        _display(
            f"Update available: {incoming} commit(s), {local[:12]} -> {remote[:12]}",
            level="warning",
        )
        if args.check_only:
            return 0
        if not _working_tree_clean():
            raise RuntimeError(
                "Working tree has local changes; commit or stash them before updating"
            )

        result = _git("merge", "--ff-only", remote, timeout=180)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "Fast-forward update failed")
        _display("Source updated. Verifying the installed CLI")
        _install(args.allowed_domains)
        _display(f"Update complete at {remote[:12]}", level="success")
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        _display(str(exc), level="error")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
