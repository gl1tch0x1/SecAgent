"""Bounded, read-only browser discovery for the default scan inventory."""

from __future__ import annotations

from collections import deque
from urllib.parse import urljoin

from secagents.infra.execution_budget import BudgetExceeded, ExecutionBudget
from secagents.infra.scope import ScopeViolationError, enforce_scope


async def discover_browser(
    target_url: str,
    budget: ExecutionBudget,
    *,
    max_depth: int = 1,
    max_pages: int = 10,
    auth_headers: dict[str, str] | None = None,
) -> dict:
    """Collect scoped browser requests and DOM links without submitting forms."""
    enforce_scope(target_url)
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"status": "skipped", "reason": "Playwright is not installed", "urls": []}

    found: set[str] = {target_url}
    visited: set[str] = set()
    queue = deque([(target_url, 0)])
    blocked = 0
    errors: list[str] = []
    forms: list[dict[str, str]] = []
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, channel="chromium")
            context = await browser.new_context(
                ignore_https_errors=False,
                extra_http_headers=auth_headers or {},
                service_workers="block",
            )

            async def route_request(route):
                nonlocal blocked
                request = route.request
                url = request.url
                try:
                    enforce_scope(url)
                    if request.method not in {"GET", "HEAD"}:
                        raise ScopeViolationError("Browser write request blocked")
                    async with budget.request(url):
                        response = await route.fetch(max_redirects=0)
                    found.add(url)
                    await route.fulfill(response=response)
                except (ScopeViolationError, BudgetExceeded):
                    blocked += 1
                    await route.abort()

            await context.route("**/*", route_request)
            page = await context.new_page()
            while (
                queue and len(visited) < max_pages and not budget.snapshot()["termination_reason"]
            ):
                url, depth = queue.popleft()
                if url in visited:
                    continue
                visited.add(url)
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    links = await page.eval_on_selector_all(
                        "a[href]", "nodes => nodes.map(node => node.getAttribute('href'))"
                    )
                    page_forms = await page.eval_on_selector_all(
                        "form[action]",
                        "nodes => nodes.map(node => ({action: node.getAttribute('action'), method: (node.getAttribute('method') || 'GET').toUpperCase()}))",
                    )
                    for form in page_forms[:100]:
                        action = urljoin(url, form.get("action") or "")
                        try:
                            enforce_scope(action)
                        except ScopeViolationError:
                            continue
                        method = form.get("method", "GET")
                        forms.append({"method": method, "url": action})
                        if method == "GET":
                            found.add(action)
                    for href in links[:100]:
                        candidate = urljoin(url, href)
                        try:
                            enforce_scope(candidate)
                        except ScopeViolationError:
                            continue
                        found.add(candidate)
                        if (
                            depth < max_depth
                            and candidate not in visited
                            and len(queue) < max_pages * 3
                        ):
                            queue.append((candidate, depth + 1))
                except Exception as exc:
                    errors.append(f"{url}: {type(exc).__name__}")
            await browser.close()
    except Exception as exc:
        return {
            "status": "failed",
            "reason": f"Browser could not run: {type(exc).__name__}",
            "urls": sorted(found),
            "blocked_requests": blocked,
        }

    return {
        "status": "partial"
        if errors or blocked or budget.snapshot()["termination_reason"]
        else "completed",
        "urls": sorted(found),
        "pages_visited": len(visited),
        "blocked_requests": blocked,
        "errors": errors[:10],
        "form_templates": forms[:500],
    }
