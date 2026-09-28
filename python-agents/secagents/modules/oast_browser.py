"""Operator-controlled OAST provider adapter and optional browser helpers."""

from __future__ import annotations

import asyncio
import os
import re
import secrets
from urllib.parse import urlsplit

import httpx

from secagents.infra.execution_budget import ExecutionBudget


_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class OASTClient:
    """Register and poll a SecAgents-compatible OAST service; no default host."""

    def __init__(
        self,
        server: str = "",
        *,
        token: str = "",
        budget: ExecutionBudget | None = None,
        client: httpx.AsyncClient | None = None,
    ):
        self.server = server.rstrip("/")
        self.token = token
        self.budget = budget
        self._client = client
        self._registration_id: str | None = None
        self._nonce: str | None = None
        self._callback_url: str | None = None

    def _check_config(self) -> None:
        parsed = urlsplit(self.server)
        approved = {
            name.strip().lower()
            for name in os.environ.get("OAST_PROVIDER_DOMAINS", "").split(",")
            if name.strip()
        }
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.hostname not in approved
            or parsed.port not in {None, 443}
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
            or not self.token
            or not self.budget
        ):
            raise RuntimeError("An approved HTTPS OAST provider, token and budget are required")

    async def _send(self, method: str, url: str, **kwargs) -> httpx.Response:
        self._check_config()
        if urlsplit(url).netloc != urlsplit(self.server).netloc:
            raise RuntimeError("OAST request changed provider origin")
        assert self.budget is not None
        if self._client is None:
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                async with self.budget.provider_request(url):
                    return await client.request(method, url, **kwargs)
        async with self.budget.provider_request(url):
            return await self._client.request(method, url, **kwargs)

    async def register(self) -> str:
        """Request a unique callback URL, then verify its approved host."""
        self._check_config()
        self._nonce = secrets.token_hex(16)
        response = await self._send(
            "POST",
            self.server + "/registrations",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"nonce": self._nonce},
        )
        response.raise_for_status()
        data = response.json()
        identifier = data.get("registration_id", "")
        callback = data.get("callback_url", "")
        parsed = urlsplit(callback)
        allowed = {
            name.strip().lower()
            for name in os.environ.get("OAST_CALLBACK_DOMAINS", "").split(",")
            if name.strip()
        }
        if (
            not isinstance(identifier, str)
            or not _IDENTIFIER.fullmatch(identifier)
            or not isinstance(callback, str)
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.hostname not in allowed
            or parsed.port not in {None, 443}
            or parsed.username
            or parsed.password
        ):
            raise RuntimeError("OAST provider returned an unapproved registration")
        self._registration_id = identifier
        self._callback_url = callback
        return callback

    async def poll(self, timeout: int = 15) -> list[dict]:
        """Only accept provider events bound to this registration and nonce."""
        if not self._registration_id or not self._nonce:
            raise RuntimeError("OAST registration is required before polling")
        deadline = asyncio.get_running_loop().time() + min(timeout, 15)
        while True:
            response = await self._send(
                "GET",
                self.server + "/registrations/" + self._registration_id + "/events",
                headers={"Authorization": f"Bearer {self.token}"},
            )
            response.raise_for_status()
            data = response.json()
            events = data.get("events", [])
            if not isinstance(events, list):
                raise RuntimeError("OAST event response is malformed")
            matched = [
                event
                for event in events
                if isinstance(event, dict)
                and event.get("registration_id") == self._registration_id
                and event.get("nonce") == self._nonce
            ]
            if matched or asyncio.get_running_loop().time() >= deadline:
                return matched
            await asyncio.sleep(min(1.0, max(0.0, deadline - asyncio.get_running_loop().time())))

    @property
    def callback_url(self) -> str | None:
        return self._callback_url


class BrowserCluster:
    """Retired unscoped browser helper; use bounded discovery and proof APIs."""

    def __init__(self, concurrency: int = 3, browser: str = "chromium"):
        self.concurrency = concurrency
        self.browser = browser
        self._sem = asyncio.Semaphore(concurrency)

    async def execute(self, url: str, script: str | None = None) -> dict:
        raise RuntimeError("Use scoped browser_discovery or browser_proof with a shared budget")

    async def check_dom_xss(self, url: str, payload: str) -> bool:
        raise RuntimeError("Use scoped browser_proof with a shared budget")


class FeedbackLoop:
    """Persists confirmed/false-positive findings for learning."""

    def __init__(self, path: str = ".secagents/feedback.json"):
        import json
        from pathlib import Path

        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict = {"confirmed": [], "false_positives": []}
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text())
            except (json.JSONDecodeError, ValueError, OSError):
                self._data = {"confirmed": [], "false_positives": []}

    def confirm(self, finding_fingerprint: str) -> None:
        if finding_fingerprint not in self._data["confirmed"]:
            self._data["confirmed"].append(finding_fingerprint)
            self._save()

    def mark_false_positive(self, finding_fingerprint: str) -> None:
        if finding_fingerprint not in self._data["false_positives"]:
            self._data["false_positives"].append(finding_fingerprint)
            self._save()

    def is_known_fp(self, fingerprint: str) -> bool:
        return fingerprint in self._data["false_positives"]

    def _save(self) -> None:
        import json

        self._path.write_text(json.dumps(self._data, indent=2))
