"""Real browser positive and negative controls for reflected XSS proof."""

from __future__ import annotations

import html
import importlib.util
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

import pytest

from secagents.crucible.browser_proof import prove_xss
from secagents.infra.execution_budget import ExecutionBudget
from secagents.modules.cve_checks import RUN_CANARY


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parts = urlsplit(self.path)
        value = parse_qs(parts.query).get("q", [""])[0]
        body = value if parts.path == "/vulnerable" else html.escape(value)
        data = f"<!doctype html><html><body>{body}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


@pytest.mark.asyncio
async def test_real_browser_xss_fixture_requires_execution_and_negative_control(
    monkeypatch,
):
    if importlib.util.find_spec("playwright") is None:
        pytest.skip("Playwright is not installed locally")
    monkeypatch.setenv("ALLOWED_DOMAINS", "127.0.0.1")
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = f"<script>alert('{RUN_CANARY}')</script>"
        spec = {"method": "GET", "param": "q", "value": payload}
        root = f"http://127.0.0.1:{server.server_address[1]}"
        budget = ExecutionBudget(
            max_requests=20,
            requests_per_second_per_host=100,
            max_duration_seconds=60,
        )
        positive = await prove_xss(
            f"{root}/vulnerable?q={quote(payload)}", spec, budget
        )
        negative = await prove_xss(f"{root}/safe?q={quote(payload)}", spec, budget)
        assert positive["validated"] is True, positive
        assert negative["validated"] is False, negative
        assert budget.snapshot()["requests_used"] <= 20
        assert budget.snapshot()["termination_reason"] is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
