#!/usr/bin/env python3
"""Smoke-test a packaged SecAgent binary or CLI entry-point."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

DEFAULT_ARGS = ["--help"]


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


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a packaged SecAgent artifact launches successfully.")
    parser.add_argument("--binary", required=True, help="Path to the packaged CLI artifact")
    parser.add_argument("--args", nargs="*", default=None, help="Arguments to pass to the packaged binary (defaults to --help)")
    parser.add_argument("--timeout", type=int, default=30, help="Seconds to wait before failing the smoke check")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        completed = run_release_smoke_check(args.binary, args.args, timeout=args.timeout)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except subprocess.TimeoutExpired as exc:
        print(f"Release smoke test timed out after {args.timeout}s", file=sys.stderr)
        if exc.stdout:
            print(exc.stdout, file=sys.stdout)
        if exc.stderr:
            print(exc.stderr, file=sys.stderr)
        return 3

    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)

    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
