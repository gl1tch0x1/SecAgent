"""Scope-checked browser execution proof for reflected GET XSS candidates."""

from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from secagents.infra.execution_budget import BudgetExceeded, ExecutionBudget
from secagents.infra.scope import ScopeViolationError, enforce_scope
from secagents.modules.cve_checks import RUN_CANARY


def _control_url(url: str, parameter: str, injected_value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not any(name == parameter and value == injected_value for name, value in pairs):
        raise ValueError("XSS candidate does not contain its declared payload")
    control = [
        (name, "secagent_negative_control" if name == parameter else value) for name, value in pairs
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(control), ""))


async def prove_xss(
    url: str,
    payload: dict,
    budget: ExecutionBudget,
    auth_headers: dict[str, str] | None = None,
) -> dict:
    """Require an exact canary dialog in two independent runs and none in control."""
    enforce_scope(url)
    if payload.get("method") != "GET" or not payload.get("param"):
        return {
            "validated": False,
            "status": "inconclusive",
            "reason": "Browser proof requires a GET parameter",
        }
    value = str(payload.get("value", ""))
    if RUN_CANARY not in value:
        return {
            "validated": False,
            "status": "inconclusive",
            "reason": "Candidate lacks the scan canary",
        }
    control_url = _control_url(url, str(payload["param"]), value)
    enforce_scope(control_url)
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"validated": False, "status": "inconclusive", "reason": "Playwright is unavailable"}

    observations: list[dict] = []
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, channel="chromium")
            try:
                for role, test_url in (
                    ("negative_control", control_url),
                    ("positive_probe", url),
                    ("positive_replay", url),
                ):
                    context = await browser.new_context(
                        extra_http_headers=auth_headers or {},
                        ignore_https_errors=False,
                        service_workers="block",
                    )
                    try:
                        page = await context.new_page()
                        dialogs: list[str] = []
                        blocked = 0

                        async def on_dialog(dialog):
                            dialogs.append(dialog.message)
                            await dialog.dismiss()

                        async def on_route(route):
                            nonlocal blocked
                            request = route.request
                            try:
                                enforce_scope(request.url)
                                if request.method not in {"GET", "HEAD"}:
                                    raise ScopeViolationError("Browser write request blocked")
                                async with budget.request(request.url):
                                    response = await route.fetch(max_redirects=0)
                                await route.fulfill(response=response)
                            except (ScopeViolationError, BudgetExceeded):
                                blocked += 1
                                await route.abort()

                        page.on("dialog", on_dialog)
                        await context.route("**/*", on_route)
                        response = await page.goto(
                            test_url, wait_until="domcontentloaded", timeout=15000
                        )
                        await page.wait_for_timeout(250)
                        matched = RUN_CANARY in dialogs
                        observations.append(
                            {
                                "role": role,
                                "status_code": response.status if response else None,
                                "canary_dialog": matched,
                                "dialog_count": len(dialogs),
                                "dialog_sha256": [
                                    hashlib.sha256(message.encode()).hexdigest()
                                    for message in dialogs
                                ],
                                "blocked_requests": blocked,
                            }
                        )
                    finally:
                        await context.close()
            finally:
                await browser.close()
    except Exception as exc:
        return {
            "validated": False,
            "status": "inconclusive",
            "reason": f"Browser proof could not complete: {type(exc).__name__}",
            "observations": observations,
        }

    valid = (
        len(observations) == 3
        and not observations[0]["canary_dialog"]
        and all(item["canary_dialog"] for item in observations[1:])
        and all(
            item["status_code"] is not None and item["status_code"] < 400 for item in observations
        )
    )
    return {
        "validated": valid,
        "status": "validated" if valid else "rejected",
        "reason": "Exact canary dialog reproduced in browser"
        if valid
        else "Browser control or replay did not establish XSS",
        "observations": observations,
    }
