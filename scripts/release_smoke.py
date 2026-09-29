#!/usr/bin/env python3
"""Smoke-test a packaged SecAgent binary or CLI entry-point."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ARGS = ["--help"]


@dataclass(frozen=True)
class ReleaseArtifactProof:
    """Release proof that a packaged artifact boots and exposes stable CLI metadata."""

    return_code: int
    help_text: str | None
    version: str | None


def _build_command(binary_path: Path) -> list[str]:
    executable = binary_path.expanduser()
    suffix = executable.suffix.lower()
    if os.name == "nt" and suffix not in {".exe", ".com", ".bat", ".cmd", ".ps1"}:
        return [sys.executable, str(executable)]
    return [str(executable)]


def run_release_smoke_check(binary_path: str, args: list[str] | None = None, timeout: int = 30, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Execute the packaged binary and return its raw process result."""
    resolved = Path(binary_path).expanduser()
    if not resolved.exists():
        raise FileNotFoundError(f"Release artifact not found: {resolved}")

    cmd = _build_command(resolved)
    cmd.extend(args or DEFAULT_ARGS)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )


def validate_release_artifact(
    binary_path: str,
    timeout: int = 30,
    env: dict[str, str] | None = None,
    expected_version: str | None = None,
) -> ReleaseArtifactProof:
    """Require proof that the artifact boots and exposes a version + help message."""
    help_run = run_release_smoke_check(binary_path, ["--help"], timeout=timeout, env=env)
    version_run = run_release_smoke_check(binary_path, ["--version"], timeout=timeout, env=env)

    raw_help = (help_run.stdout or "") + (help_run.stderr or "")
    raw_version = (version_run.stdout or "") + (version_run.stderr or "")
    version_match = re.search(
        r"(?:SecAgent|secagent)[^0-9]*([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?)",
        raw_version,
        flags=re.IGNORECASE,
    )
    version = version_match.group(1) if version_match else None

    if help_run.returncode != 0:
        raise ValueError(f"Release artifact did not boot successfully with --help: {help_run.returncode}")
    if version_run.returncode != 0:
        raise ValueError(f"Release artifact did not emit a valid version string: {version_run.returncode}")
    if not raw_help or not re.search(r"usage|help", raw_help, flags=re.IGNORECASE):
        raise ValueError("Release artifact did not expose usable help text")
    if version is None:
        raise ValueError("Release artifact did not expose a Semantic Version")
    if expected_version is not None and version != expected_version:
        raise ValueError(
            f"Release artifact version mismatch: expected {expected_version}, found {version}"
        )

    return ReleaseArtifactProof(
        return_code=0,
        help_text=raw_help.strip() or None,
        version=version,
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a packaged SecAgent artifact launches successfully.")
    parser.add_argument("--binary", required=True, help="Path to the packaged CLI artifact")
    parser.add_argument("--args", nargs="*", default=None, help="Arguments to pass to the packaged binary (defaults to --help)")
    parser.add_argument("--timeout", type=int, default=30, help="Seconds to wait before failing the smoke check")
    parser.add_argument("--expected-version", help="Require the artifact to report this exact release version")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        proof = validate_release_artifact(
            args.binary,
            timeout=args.timeout,
            expected_version=args.expected_version,
        )
        if args.args:
            completed = run_release_smoke_check(args.binary, args.args, timeout=args.timeout)
        else:
            completed = run_release_smoke_check(args.binary, ["--help"], timeout=args.timeout)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (subprocess.TimeoutExpired, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 3

    if args.args:
        if completed.stdout:
            print(completed.stdout, end="")
        if completed.stderr:
            print(completed.stderr, end="", file=sys.stderr)
        return completed.returncode

    if proof.help_text:
        print(proof.help_text)
    if proof.version:
        print(f"Version: {proof.version}")
    return proof.return_code


if __name__ == "__main__":
    raise SystemExit(main())
