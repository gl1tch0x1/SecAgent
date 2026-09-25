"""Shared limits for HTTP requests made by an authorized scan."""

from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from secagents.infra.scope import enforce_scope


class BudgetExceeded(RuntimeError):
    """The scan must stop issuing requests because a configured limit was hit."""


class ExecutionBudget:
    def __init__(
        self,
        *,
        max_requests: int = 1000,
        requests_per_second_per_host: float = 5.0,
        max_concurrency: int = 8,
        max_duration_seconds: float = 900.0,
    ) -> None:
        if (
            min(max_requests, requests_per_second_per_host, max_concurrency, max_duration_seconds)
            <= 0
        ):
            raise ValueError("All execution limits must be positive")
        self.max_requests = max_requests
        self.requests_per_second_per_host = requests_per_second_per_host
        self.max_concurrency = max_concurrency
        self.max_duration_seconds = max_duration_seconds
        self._started = time.monotonic()
        self._used = 0
        self._in_flight = 0
        self._peak_in_flight = 0
        self._termination_reason: str | None = None
        self._last_by_host: dict[str, float] = defaultdict(float)
        self._lock = asyncio.Lock()
        self._host_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._semaphore = asyncio.Semaphore(max_concurrency)

    def remaining_seconds(self) -> float:
        return max(0.0, self.max_duration_seconds - (time.monotonic() - self._started))

    def _check_deadline(self) -> None:
        if self.remaining_seconds() <= 0:
            self._termination_reason = "deadline_exceeded"
            raise BudgetExceeded("Scan deadline exceeded")

    @asynccontextmanager
    async def request(self, url: str):
        """Reserve one scoped HTTP request before it is sent."""
        enforce_scope(url)
        async with self._reserve(url):
            yield

    @asynccontextmanager
    async def provider_request(self, url: str):
        """Reserve a request to one explicitly supported intelligence API."""
        parsed = urlsplit(url)
        approved_hosts = {"api.shodan.io", "dns.projectdiscovery.io"}
        approved_hosts.update(
            host.strip().lower()
            for host in os.environ.get("OAST_PROVIDER_DOMAINS", "").split(",")
            if host.strip()
        )
        if (
            parsed.scheme != "https"
            or parsed.hostname not in approved_hosts
            or parsed.port not in {None, 443}
            or parsed.username
            or parsed.password
        ):
            raise PermissionError("Intelligence provider endpoint is not approved")
        async with self._reserve(url):
            yield

    @asynccontextmanager
    async def _reserve(self, url: str):
        self._check_deadline()
        try:
            await asyncio.wait_for(self._semaphore.acquire(), timeout=self.remaining_seconds())
        except TimeoutError as exc:
            self._termination_reason = "deadline_exceeded"
            raise BudgetExceeded("Scan deadline exceeded while waiting for a slot") from exc
        counted = False
        try:
            host = urlsplit(url).hostname or url.split("/")[0]
            async with self._host_locks[host]:
                self._check_deadline()
                wait = max(
                    0.0,
                    self._last_by_host[host]
                    + 1.0 / self.requests_per_second_per_host
                    - time.monotonic(),
                )
                if wait >= self.remaining_seconds():
                    self._termination_reason = "deadline_exceeded"
                    raise BudgetExceeded("Scan deadline exceeded during rate limit")
                if wait:
                    await asyncio.sleep(wait)
                self._check_deadline()
                async with self._lock:
                    if self._used >= self.max_requests:
                        self._termination_reason = "request_limit_exceeded"
                        raise BudgetExceeded("Scan request limit exceeded")
                    self._used += 1
                    self._in_flight += 1
                    self._peak_in_flight = max(self._peak_in_flight, self._in_flight)
                    counted = True
                self._last_by_host[host] = time.monotonic()
            yield
        finally:
            if counted:
                async with self._lock:
                    self._in_flight -= 1
            self._semaphore.release()

    def snapshot(self) -> dict:
        return {
            "requests_used": self._used,
            "request_limit": self.max_requests,
            "per_host_rate_limit": self.requests_per_second_per_host,
            "concurrency_limit": self.max_concurrency,
            "peak_concurrency": self._peak_in_flight,
            "elapsed_seconds": round(time.monotonic() - self._started, 3),
            "duration_limit_seconds": self.max_duration_seconds,
            "termination_reason": self._termination_reason,
        }
