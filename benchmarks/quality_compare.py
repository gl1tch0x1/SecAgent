"""Run both scanners against identical local positive and negative web fixtures.

This records raw reports, wall time, and observed fixture requests. It does not
turn scanner-specific finding labels into accuracy claims automatically.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


class Fixture(BaseHTTPRequestHandler):
    vulnerable = False
    requests_seen = 0
    server_version = "Fixture"
    sys_version = ""

    def do_HEAD(self):
        self._respond(with_body=False)

    def do_GET(self):
        self._respond(with_body=True)

    def _respond(self, *, with_body: bool):
        type(self).requests_seen += 1
        parts = urlsplit(self.path)
        value = parse_qs(parts.query).get("q", [""])[0]
        status = 200
        content_type = "text/html; charset=utf-8"
        if parts.path == "/":
            body = (
                '<a href="/search?q=sample">Search</a><a href="/xss?q=sample">XSS</a>'
            )
        elif parts.path == "/search":
            body = (
                "You have an error in your SQL syntax"
                if self.vulnerable and "'" in value
                else "Normal search results"
            )
        elif parts.path == "/xss":
            body = value if self.vulnerable else html.escape(value)
        elif parts.path == "/.git/config" and self.vulnerable:
            body = "[core]\nrepositoryformatversion = 0"
            content_type = "text/plain"
        else:
            status, body = 404, "Not found"
        data = f"<!doctype html><html><body>{body}</body></html>".encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        self.end_headers()
        if with_body:
            self.wfile.write(data)

    def log_message(self, format, *args):
        pass


def scan(command: list[str], env: dict[str, str], output: Path, timeout: int) -> dict:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            env=env,
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        output.write_text(
            completed.stdout + "\n--- STDERR ---\n" + completed.stderr,
            encoding="utf-8",
        )
        return {
            "exit_code": completed.returncode,
            "duration_seconds": round(time.monotonic() - started, 2),
        }
    except subprocess.TimeoutExpired as exc:
        output.write_text(f"Timed out after {timeout}s: {exc}", encoding="utf-8")
        return {
            "exit_code": None,
            "duration_seconds": round(time.monotonic() - started, 2),
            "timeout": True,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--akca-binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("benchmark-results"))
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--request-budget", type=int, default=800)
    parser.add_argument("--time-budget-seconds", type=int, default=180)
    parser.add_argument(
        "--engine", choices=("both", "secagent", "akca"), default="both"
    )
    parser.add_argument(
        "--fixture", choices=("both", "positive", "negative"), default="both"
    )
    parser.add_argument("--akca-modes", default="sql,xss")
    args = parser.parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    env = os.environ.copy()
    for name in (
        "SHODAN_API_KEY",
        "CHAOS_API_KEY",
        "SLACK_WEBHOOK_URL",
        "JIRA_URL",
        "JIRA_API_TOKEN",
    ):
        env.pop(name, None)
    env["ALLOWED_DOMAINS"] = "127.0.0.1"
    env["BLOCKED_DOMAINS"] = ""
    env["NO_COLOR"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["TERM"] = "dumb"
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "python-agents")
    for vulnerable in (True, False):
        kind = "positive" if vulnerable else "negative"
        if args.fixture != "both" and args.fixture != kind:
            continue
        handler = type(
            f"{kind.title()}Fixture",
            (Fixture,),
            {"vulnerable": vulnerable, "requests_seen": 0},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        target = f"http://127.0.0.1:{server.server_address[1]}/"
        try:
            for engine in ("secagent", "akca"):
                if args.engine != "both" and args.engine != engine:
                    continue
                handler.requests_seen = 0
                prefix = output_dir / f"{engine}-{kind}"
                if engine == "secagent":
                    command = [
                        sys.executable,
                        "-m",
                        "secagents.cli",
                        "scan",
                        "--target",
                        target,
                        "--depth",
                        "quick",
                        "--skip-os-check",
                        "--no-arsenal",
                        "--max-requests",
                        str(args.request_budget),
                        "--rate-limit",
                        "30",
                        "--max-duration",
                        str(args.time_budget_seconds),
                        "--results-dir",
                        str(prefix),
                    ]
                else:
                    command = [
                        str(args.akca_binary.resolve()),
                        "-u",
                        target,
                        "-m",
                        args.akca_modes,
                        "--no-oast",
                        "--no-fuzzing",
                        "--crawler-budget",
                        "50",
                        "--max-pages",
                        "10",
                        "--max-endpoints",
                        "10",
                        "--request-budget",
                        str(args.request_budget),
                        "--rate-limit",
                        "30",
                        "--time-budget",
                        f"{args.time_budget_seconds}s",
                        "--max-depth",
                        "1",
                        "-f",
                        "json",
                        "-o",
                        str(prefix) + ".json",
                    ]
                observed = scan(command, env, Path(str(prefix) + ".log"), args.timeout)
                observed.update(
                    engine=engine,
                    fixture=kind,
                    target=target,
                    fixture_requests=handler.requests_seen,
                    request_budget=args.request_budget,
                    time_budget_seconds=args.time_budget_seconds,
                )
                results.append(observed)
                print(json.dumps(observed), flush=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    runs_file = output_dir / "runs.json"
    if runs_file.exists():
        try:
            previous = json.loads(runs_file.read_text(encoding="utf-8"))
            if isinstance(previous, list):
                results = previous + results
        except (OSError, ValueError):
            pass
    runs_file.write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
