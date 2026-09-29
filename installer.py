#!/usr/bin/env python3
# ruff: noqa: E402
"""
╔══════════════════════════════════════════════════════════════════╗
║          SecAgents — Elite Red Team Deployment Engine           ║
║       "Precision. Intelligence. Multi-Agent Mastery."           ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import argparse
from importlib.util import find_spec
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional


def bootstrap_rich():
    if find_spec("rich") is not None:
        return True
    print("[>] Installing terminal display dependency...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "rich", "--quiet"], check=True
        )
        return True
    except (subprocess.CalledProcessError, OSError) as e:
        print(f"[x] Bootstrap failed ({e}). Install 'rich' manually: pip install rich")
        return False


if not bootstrap_rich():
    sys.exit(1)

from rich.console import Console
from rich.console import Group
from rich.columns import Columns
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.theme import Theme
from rich.box import ROUNDED, HEAVY

# ─── Aesthetic Configuration ────────────────────────────────────────────────
custom_theme = Theme(
    {
        "info": "bold #00ffff",
        "warning": "bold #ffaa00",
        "error": "bold #ff003c",
        "success": "bold #00ff00",
        "phase": "bold #ff00ff",
        "hacker": "bold #00ff00",
        "highlight": "bold white on #0066ff",
        "dim": "grey50",
    }
)

console = Console(theme=custom_theme)
IS_WIN = platform.system() == "Windows"

# ─── Paths ───────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.resolve()
VENV_DIR = ROOT / "venv" if (ROOT / "venv").exists() else ROOT / ".venv"
PYTHON_AGENTS = ROOT / "python-agents"
ENV_FILE = ROOT / ".env"

PYTHON_EXEC = str(
    VENV_DIR / ("Scripts" if IS_WIN else "bin") / ("python.exe" if IS_WIN else "python")
)
PIP_EXEC = str(
    VENV_DIR / ("Scripts" if IS_WIN else "bin") / ("pip.exe" if IS_WIN else "pip")
)
PYTEST_EXEC = str(
    VENV_DIR / ("Scripts" if IS_WIN else "bin") / ("pytest.exe" if IS_WIN else "pytest")
)

# ─── UI Components ───────────────────────────────────────────────────────────

BANNER = r"""
      _____           ___                    __
     / ___/___  _____/   | ____ ____  ____  / /______
     \__ \/ _ \/ ___/ /| |/ __ `/ _ \/ __ \/ __/ ___/
    ___/ /  __/ /__/ ___ / /_/ /  __/ / / / /_(__  )
   /____/\___/\___/_/  |_\__, /\___/_/ /_/_/   \___/
                        /____/
"""


def get_header():
    title = Text(BANNER, style="hacker")
    subtitle = Text(
        "// OFFENSIVE TOOLCHAIN ARMING SEQUENCE // AUTHORIZED TARGETS ONLY",
        style="bold cyan",
    )
    return Panel(
        Group(title, subtitle), border_style="green", box=HEAVY, padding=(0, 1)
    )


class DeploymentUI:
    def __init__(self):
        self.phases: list[tuple[str, str]] = []
        self.log_messages: list[str] = []
        self.active_phase = "BOOTSTRAP"

    def update_log(self, message: str, style: str = "info"):
        timestamp = time.strftime("%H:%M:%S")
        prefixes = {"info": "[>]", "success": "[+]", "warning": "[!]", "error": "[x]"}
        self.log_messages.append(f"{timestamp} {prefixes.get(style, '[>]')} {message}")
        if len(self.log_messages) > 9:
            self.log_messages.pop(0)

    def add_phase(self, name: str, status: str = "[dim]PENDING[/dim]"):
        self.phases.append((name, status))

    def update_phase(self, index: int, status: str):
        self.phases[index] = (self.phases[index][0], status)

    def render(self):
        phases = Table(
            title="[bold magenta]MISSION LOADOUT[/bold magenta]", box=ROUNDED
        )
        phases.add_column("#", width=3, style="dim")
        phases.add_column("MODULE", min_width=15)
        phases.add_column("STATE", justify="right", min_width=11)
        for index, (name, status) in enumerate(self.phases, 1):
            phases.add_row(f"{index:02d}", name, status)
        telemetry = Panel(
            "\n".join(self.log_messages) or "Awaiting installer events",
            title="[bold cyan]SIGNAL FEED[/bold cyan]",
            border_style="cyan",
            height=max(5, min(12, len(self.log_messages) + 3)),
        )
        return Group(
            get_header(),
            Columns([phases, telemetry], expand=True, equal=False),
            Panel(
                f"[bold white]ACTIVE MODULE[/bold white]  {self.active_phase}",
                border_style="magenta",
            ),
        )


ui = DeploymentUI()

# ─── Execution Logic ──────────────────────────────────────────────────────────


def run_cmd(
    cmd: list[str], cwd: Optional[Path] = None, timeout: int = 900
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


# ═══════════════════════════════════════════════════════════════════════
#  OPERATIONAL PHASES
# ═══════════════════════════════════════════════════════════════════════


def run_preflight(args: argparse.Namespace) -> bool:
    ui.update_log("Initiating preflight reconnaissance...")
    # Python Check
    v = sys.version_info
    if v >= (3, 11):
        ui.update_log(f"Runtime: Python {v.major}.{v.minor} [OK]", "success")
    else:
        ui.update_log(f"Runtime: Incompatible Python {v.major}.{v.minor}", "error")
        return False

    for tool in ["git", "docker", "node"]:
        if shutil.which(tool):
            ui.update_log(f"Binary: {tool} [FOUND]", "success")
        else:
            ui.update_log(f"Binary: {tool} [MISSING]", "warning")

    return True


def deploy_environment() -> bool:
    ui.update_log("Hardening execution environment...")
    if not VENV_DIR.exists():
        try:
            result = run_cmd([sys.executable, "-m", "venv", str(VENV_DIR)], timeout=180)
            if result.returncode != 0:
                ui.update_log(
                    f"Environment setup failed: {result.stderr[-160:]}", "error"
                )
                return False
            ui.update_log("Isolated tunnel (venv) established.", "success")
        except Exception as e:
            ui.update_log(f"Environment collapse: {e}", "error")
            return False
    return True


def install_arsenal(args: argparse.Namespace) -> bool:
    ui.update_log("Arming the offensive arsenal...")

    packages = [
        ("Core Agents Framework", PYTHON_AGENTS, ".[dev,browser]"),
    ]
    for name, path, extras in packages:
        if not path.exists():
            ui.update_log(f"Required package path missing: {path}", "error")
            return False
        ui.update_log(f"Mounting {name}...")
        res = run_cmd([PIP_EXEC, "install", "--prefer-binary", "-e", extras], cwd=path)
        if res.returncode != 0:
            ui.update_log(f"{name} mount failed: {res.stderr[-160:]}", "error")
            return False
    return True


def configure_intel(args: argparse.Namespace) -> bool:
    ui.update_log("Configuring operator authorization manifest...")
    if not ENV_FILE.exists():
        ENV_FILE.write_text(
            f"JWT_SECRET={secrets.token_urlsafe(48)}\n", encoding="utf-8"
        )
        ui.update_log("Local .env created without a default target scope.", "success")
    if args.allowed_domains:
        domains = [
            item.strip().lower()
            for item in args.allowed_domains.split(",")
            if item.strip()
        ]
        valid_label = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        if not domains or any(
            len(domain) > 253
            or not all(
                valid_label.fullmatch(label)
                for label in domain.removeprefix("*.").split(".")
            )
            for domain in domains
        ):
            ui.update_log(
                "Invalid --allowed-domains value; use comma-separated DNS names.",
                "error",
            )
            return False
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
        lines = [line for line in lines if not line.startswith("ALLOWED_DOMAINS=")]
        lines.append("ALLOWED_DOMAINS=" + ",".join(dict.fromkeys(domains)))
        ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ui.update_log("Explicit target allowlist saved.", "success")
    elif not any(
        line.startswith("ALLOWED_DOMAINS=")
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines()
    ):
        ui.update_log(
            "Target scope unset. Run 'secagent scope --add DOMAIN' before scanning.",
            "warning",
        )
    return True


def create_entrypoints() -> bool:
    ui.update_log("Deploying operational entrypoints...")
    if IS_WIN:
        (ROOT / "secagent.bat").write_text(
            f'@echo off\r\n"{PYTHON_EXEC}" -m secagents %*\r\n', encoding="utf-8"
        )
    else:
        p = ROOT / "secagent"
        p.write_text(
            f'#!/bin/sh\nexec "{PYTHON_EXEC}" -m secagents "$@"\n', encoding="utf-8"
        )
        p.chmod(0o755)
        # Attempt system PATH placement on Linux/macOS (e.g. /usr/local/bin or ~/.local/bin)
        target_dirs = [Path("/usr/local/bin"), Path.home() / ".local" / "bin"]
        for target_dir in target_dirs:
            if target_dir.exists() and os.access(target_dir, os.W_OK):
                try:
                    sym = target_dir / "secagent"
                    if sym.is_symlink() and sym.resolve() == p.resolve():
                        sym.unlink()
                    elif sym.exists() or sym.is_symlink():
                        ui.update_log(
                            f"Existing command at {sym} left untouched.", "warning"
                        )
                        continue
                    sym.symlink_to(p.resolve())
                    ui.update_log(f"Linked global entrypoint to {sym}", "success")
                    break
                except OSError as err:
                    ui.update_log(f"Could not link to {target_dir}: {err}", "warning")
    return True


def run_tests() -> bool:
    ui.update_log("Verifying the installed CLI entrypoint...")
    res = run_cmd([PYTHON_EXEC, "-m", "secagents", "--help"], cwd=ROOT, timeout=30)
    if res.returncode == 0:
        ui.update_log("CLI command verified.", "success")
        return True
    ui.update_log(f"CLI verification failed: {res.stderr[-160:]}", "error")
    return False


def print_final_report(success: bool, verified: bool = True):
    console.print("\n" + "━" * 70, style="phase")
    if success:
        console.print(
            Panel(
                Text(
                    "INSTALL COMPLETE // CLI VERIFIED"
                    if verified
                    else "INSTALL COMPLETE // CLI CHECK SKIPPED",
                    style="success",
                    justify="center",
                ),
                border_style="success",
                box=HEAVY,
            )
        )
    else:
        console.print(
            Panel(
                Text(
                    "INSTALL FAILED // REVIEW THE SIGNAL FEED",
                    style="error",
                    justify="center",
                ),
                border_style="error",
                box=HEAVY,
            )
        )
        for message in ui.log_messages[-5:]:
            console.print(message)
        return

    table = Table(box=None, expand=True)
    table.add_column("COMMAND", style="cyan", width=25)
    table.add_column("DESCRIPTION", style="dim")

    cli = ".\\secagent.bat" if IS_WIN else "./secagent"
    configured = ""
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if line.startswith("ALLOWED_DOMAINS="):
                configured = line.partition("=")[2].split(",")[0].removeprefix("*.")
                break
    if configured:
        table.add_row(f"{cli} scope --list", "Review authorized target scope")
    else:
        table.add_row(
            f"{cli} scope --add YOUR_DOMAIN",
            "Authorize a real domain you own or may assess",
        )
    table.add_row(
        f"{cli} scan -t {configured or 'YOUR_DOMAIN'}",
        "Scan the authorized domain",
    )
    table.add_row(f"{cli} --help", "Show every supported command and option")

    console.print(table)
    console.print("━" * 70, style="phase")
    console.print(
        "Operator scope is required. Installation never authorizes a target for you.",
        style="dim",
        justify="center",
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker", action="store_true")
    parser.add_argument("--no-test", action="store_true")
    parser.add_argument("--no-start", action="store_true")
    parser.add_argument(
        "--allowed-domains",
        help="Explicit comma-separated target domains to authorize in .env",
    )
    args = parser.parse_args()

    phases = [
        ("PREFLIGHT", lambda: run_preflight(args)),
        ("ENVIRONMENT", deploy_environment),
        ("ARSENAL", lambda: install_arsenal(args)),
        ("SCOPE", lambda: configure_intel(args)),
        ("ENTRYPOINTS", create_entrypoints),
    ]
    if not args.no_test:
        phases.append(("INTEGRITY", run_tests))

    for name, _ in phases:
        ui.add_phase(name)

    overall_success = True

    with Live(
        ui.render(), console=console, refresh_per_second=4, screen=console.is_terminal
    ) as live:
        for i, (name, func) in enumerate(phases):
            ui.update_phase(i, "[yellow]ACTIVE[/yellow]")
            ui.active_phase = name
            live.update(ui.render())

            try:
                if func():
                    ui.update_phase(i, "[green]SUCCESS[/green]")
                else:
                    ui.update_phase(i, "[red]FAILED[/red]")
                    overall_success = False
                    break
            except Exception as e:
                ui.update_log(f"Phase {name} crash: {e}", "error")
                ui.update_phase(i, "[bold red]CRASH[/red]")
                overall_success = False
                break

            live.update(ui.render())
            if console.is_terminal:
                time.sleep(0.12)

    if console.is_terminal:
        console.clear()
    print_final_report(overall_success, verified=not args.no_test)
    return 0 if overall_success else 1


if __name__ == "__main__":
    sys.exit(main())
