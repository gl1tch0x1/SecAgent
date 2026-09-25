"""Preflight system checks before scan execution."""

from __future__ import annotations

import os
import shutil
import socket
import sys
from dataclasses import dataclass


@dataclass
class CheckResult:
    name: str
    passed: bool
    severity: str  # error, warning, info
    message: str
    remediation: str = ""


def run_preflight() -> list[CheckResult]:
    """Run all preflight checks. Returns list of results."""
    return [
        _check_python_version(),
        _check_packages(),
        _check_docker(),
        _check_api_keys(),
        _check_disk_space(),
        _check_network(),
    ]


def preflight_ok(results: list[CheckResult]) -> bool:
    return not any(r.severity == "error" and not r.passed for r in results)


def _check_python_version() -> CheckResult:
    v = sys.version_info
    ok = v >= (3, 11)
    return CheckResult(
        name="Python Version",
        passed=ok,
        severity="error",
        message=f"Python {v.major}.{v.minor}.{v.micro}",
        remediation="Upgrade to Python 3.11+" if not ok else "",
    )


def _check_packages() -> CheckResult:
    missing = []
    for pkg in ["pydantic", "httpx", "openai", "fastapi"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    return CheckResult(
        name="Required Packages",
        passed=len(missing) == 0,
        severity="error",
        message=f"Missing: {missing}" if missing else "All present",
        remediation=f"pip install {' '.join(missing)}" if missing else "",
    )


def _check_docker() -> CheckResult:
    has_docker = shutil.which("docker") is not None
    return CheckResult(
        name="Docker",
        passed=has_docker,
        severity="warning",
        message="Docker available" if has_docker else "Docker not found",
        remediation="Install Docker: https://docs.docker.com/get-docker/" if not has_docker else "",
    )


def _check_api_keys() -> CheckResult:
    providers = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GROQ_API_KEY"]
    found = [p for p in providers if os.environ.get(p)]
    ok = len(found) > 0
    return CheckResult(
        name="API Keys",
        passed=ok,
        severity="error",
        message=f"Found: {len(found)} provider(s)" if ok else "No API keys configured",
        remediation="Set at least one: OPENAI_API_KEY, ANTHROPIC_API_KEY, or GROQ_API_KEY",
    )


def _check_disk_space() -> CheckResult:
    try:
        import shutil
        import tempfile

        free_gb = shutil.disk_usage(tempfile.gettempdir()).free / (1024**3)

        ok = free_gb >= 1.0
        return CheckResult(
            name="Disk Space",
            passed=ok,
            severity="warning",
            message=f"{free_gb:.1f} GB free",
            remediation="Free up disk space (minimum 1GB required)" if not ok else "",
        )
    except (OSError, AttributeError, Exception):
        return CheckResult(name="Disk Space", passed=True, severity="info", message="Check skipped")


def _check_network() -> CheckResult:
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3).close()
        return CheckResult(name="Network", passed=True, severity="info", message="Connected")
    except OSError:
        return CheckResult(
            name="Network",
            passed=False,
            severity="warning",
            message="No internet connectivity",
            remediation="Check network connection (required for cloud LLM providers)",
        )
