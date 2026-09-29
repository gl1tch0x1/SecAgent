"""Module 1: Operational integrity and self-preservation."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

import httpx

OS_UPDATE_MESSAGE = (
    "⚠️ Your OS has pending security updates. "
    "Please run 'sudo apt update && sudo apt upgrade -y' and re-run the tool."
)

GITHUB_REPO = os.environ.get("SECAGENT_GITHUB_REPO", "gl1tch0x1/SecAgent")
CURRENT_VERSION = "0.3.0"


class UpdateCheckResult(NamedTuple):
    update_available: bool
    local_version: str
    remote_version: str
    message: str


def check_os_security_updates(skip: bool = False) -> tuple[bool, str]:
    """
    Query package manager for pending security updates.
    Returns (ok_to_proceed, message).
    """
    if skip:
        return True, "OS check skipped (--skip-os-check)"

    system = platform.system().lower()
    if system == "windows":
        return True, "OS update check not applicable on Windows (skipped)"

    if system == "darwin":
        return True, "OS update check not automated on macOS (skipped)"

    # Linux: apt or dnf
    if shutil.which("apt-get"):
        try:
            subprocess.run(
                ["apt-get", "update", "-qq"],
                capture_output=True,
                timeout=120,
                check=False,
            )
            result = subprocess.run(
                ["apt-get", "-s", "upgrade"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            output = result.stdout + result.stderr
            # Block only when security-pocket / CVE-related upgrades are pending
            if re.search(
                r"security|debian-security|ubuntu.*security|CVE-\d+",
                output,
                re.IGNORECASE,
            ) and re.search(r"^\d+ upgraded|inst ", output, re.IGNORECASE | re.MULTILINE):
                return False, OS_UPDATE_MESSAGE
            return True, "No pending security-related apt upgrades detected"
        except (subprocess.TimeoutExpired, OSError) as e:
            return True, f"OS check inconclusive: {e}"

    if shutil.which("dnf"):
        try:
            result = subprocess.run(
                ["dnf", "check-update", "--security"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            # dnf returns 100 when updates available
            lines = [
                ln for ln in result.stdout.splitlines() if ln.strip() and not ln.startswith("Last")
            ]
            if result.returncode == 100 or len(lines) > 2:
                return False, OS_UPDATE_MESSAGE.replace("apt", "dnf")
            return True, "No pending dnf security updates"
        except (subprocess.TimeoutExpired, OSError) as e:
            return True, f"OS check inconclusive: {e}"

    return True, "No supported package manager for OS update check"


def _parse_version(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts) if parts else (0,)


def fetch_latest_release_version(repo: str = GITHUB_REPO) -> str | None:
    """Fetch latest release tag from GitHub."""
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get(url, headers={"Accept": "application/vnd.github+json"})
            if resp.status_code == 200:
                data = resp.json()
                tag = data.get("tag_name", "")
                return tag.lstrip("v")
    except httpx.HTTPError:
        pass
    return None


def check_tool_update(local_version: str = CURRENT_VERSION) -> UpdateCheckResult:
    remote = fetch_latest_release_version()
    if not remote:
        return UpdateCheckResult(
            False, local_version, local_version, "Could not fetch remote version"
        )
    local_t = _parse_version(local_version)
    remote_t = _parse_version(remote)
    available = remote_t > local_t
    msg = (
        f"Update available: {local_version} → {remote}"
        if available
        else f"Up to date ({local_version})"
    )
    return UpdateCheckResult(available, local_version, remote, msg)


def check_and_apply_tool_update(
    root: Path | None = None,
    auto_update: bool = True,
) -> tuple[bool, str]:
    """Delegate source updates to the guarded updater; report failure honestly."""
    checkout = (root or Path.cwd()).resolve()
    script = checkout / "update.py"
    if not script.is_file():
        release_status = check_tool_update()
        suffix = (
            "; update a source checkout with update.py" if release_status.update_available else ""
        )
        return not release_status.update_available, release_status.message + suffix
    command = [sys.executable, str(script)]
    if not auto_update:
        command.append("--check-only")
    try:
        completed = subprocess.run(
            command,
            cwd=checkout,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Updater failed: {exc}"
    if completed.returncode:
        return False, f"Updater failed: {(completed.stderr or completed.stdout).strip()[-300:]}"
    return (
        True,
        "Update check completed" if not auto_update else "Update and installation completed",
    )
