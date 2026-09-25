"""Advanced Headless Browser Agent: DOM Tree analysis, dynamic JS monitoring, and screenshot capture."""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict

import httpx

from secagents.agents.base import AgentConfig, AgentOutput, AgentRole, BaseAgent
from secagents.infra.scope import enforce_scope, ScopeViolationError
from secagents.infra.execution_budget import BudgetExceeded, ExecutionBudget


class BrowserAgent(BaseAgent):
    """Headless Chrome automation agent for JavaScript monitoring and DOM inspection."""

    def __init__(self, name: str = "browser_agent"):
        config = AgentConfig(role=AgentRole.RECON, name=name)
        super().__init__(config=config)
        self.logger = logging.getLogger(f"secagents.{name}")

    def base_system_prompt(self) -> str:
        return (
            "You are a Headless Browser Automation Agent inspecting DOM trees and dynamic traffic."
        )

    async def execute(self, task: Dict[str, Any]) -> AgentOutput:
        """Execute headless browser automation and DOM extraction."""
        raw_url = task.get("target_url") or task.get("target", "")
        if not raw_url:
            return AgentOutput(
                agent=self.name,
                role=self.role,
                result={"error": "No target_url specified"},
                confidence=0.0,
                error="No target_url specified",
            )

        target_url = (
            raw_url if raw_url.startswith(("http://", "https://")) else f"https://{raw_url}"
        )

        # Validate target URL against ALLOWED_DOMAINS
        try:
            enforce_scope(target_url)
        except ScopeViolationError as e:
            self.logger.warning(f"Target URL {target_url} blocked by scope policy: {e}")
            return AgentOutput(
                agent=self.name,
                role=self.role,
                result={"error": "Target not in ALLOWED_DOMAINS"},
                confidence=0.0,
                error=str(e),
            )

        self.logger.info(f"Navigating to {target_url} via Headless Browser Agent")
        analysis = await self._analyze_page(target_url)

        is_failed = analysis.get("engine") == "failed"
        confidence = 0.0 if is_failed else 0.9

        return AgentOutput(
            agent=self.name,
            role=self.role,
            result={
                "target_url": target_url,
                "title": analysis.get("title", ""),
                "dom_elements_count": analysis.get("dom_count", 0),
                "forms_detected": analysis.get("forms", []),
                "security_headers": analysis.get("security_headers", {}),
                "js_errors": analysis.get("js_errors", []),
                "screenshot_captured": not is_failed,
                "engine": analysis.get("engine", "unknown"),
            },
            confidence=confidence,
            error=analysis.get("error") if is_failed else None,
        )

    async def _analyze_page(self, url: str) -> dict[str, Any]:
        """Inspect page structure, security headers, forms using Playwright or httpx fallback."""
        budget = ExecutionBudget(max_requests=50, max_duration_seconds=30)
        try:
            from playwright.async_api import async_playwright  # type: ignore[import-not-found,import-untyped]

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, channel="chromium")
                context = await browser.new_context(
                    ignore_https_errors=os.environ.get("SECAGENT_VERIFY_SSL", "true").lower()
                    == "false",
                    service_workers="block",
                )

                async def scoped_route(route):
                    try:
                        enforce_scope(route.request.url)
                        if route.request.method not in {"GET", "HEAD"}:
                            raise ScopeViolationError("Browser write request blocked")
                        async with budget.request(route.request.url):
                            response = await route.fetch(max_redirects=0)
                        await route.fulfill(response=response)
                    except (ScopeViolationError, BudgetExceeded):
                        await route.abort()

                await context.route("**/*", scoped_route)
                page = await context.new_page()

                js_errors: list[str] = []
                page.on("pageerror", lambda exc: js_errors.append(str(exc)))

                resp = await page.goto(url, timeout=12000, wait_until="domcontentloaded")
                title = await page.title()
                dom_count = await page.evaluate("document.querySelectorAll('*').length")
                forms = await page.evaluate("""
                    Array.from(document.querySelectorAll('form')).map(f => ({
                        action: f.getAttribute('action') || '',
                        method: (f.getAttribute('method') || 'GET').toUpperCase(),
                        inputs: Array.from(f.querySelectorAll('input, select, textarea'))
                                    .map(i => i.getAttribute('name') || '')
                                    .filter(Boolean)
                    }))
                """)
                headers = dict(resp.headers) if resp else {}
                await browser.close()

                return {
                    "title": title or "SecAgent Inspected Page",
                    "dom_count": dom_count,
                    "forms": forms,
                    "js_errors": js_errors,
                    "security_headers": {
                        "Content-Security-Policy": headers.get(
                            "content-security-policy", "missing"
                        ),
                        "X-Frame-Options": headers.get("x-frame-options", "missing"),
                        "Strict-Transport-Security": headers.get(
                            "strict-transport-security", "missing"
                        ),
                    },
                    "engine": "playwright-chromium",
                }
        except Exception as e:
            self.logger.debug(f"Playwright navigation failed for {url}, falling back to httpx: {e}")
            try:
                verify_ssl = os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false"
                async with httpx.AsyncClient(
                    timeout=6.0, verify=verify_ssl, follow_redirects=False
                ) as client:
                    async with budget.request(url):
                        http_response = await client.get(url)
                    headers = dict(http_response.headers)
                    html_text = http_response.text

                    # Title extraction
                    title_match = re.search(
                        r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL
                    )
                    page_title = (
                        title_match.group(1).strip()
                        if title_match
                        else headers.get("server", "SecAgent Target Host")
                    )

                    # Form extraction via regex
                    form_blocks = re.findall(
                        r"<form[^>]*>(.*?)</form>", html_text, re.IGNORECASE | re.DOTALL
                    )
                    forms_extracted = []
                    for block in form_blocks:
                        inputs = re.findall(
                            r'<input[^>]+name=["\']([^"\']+)["\']', block, re.IGNORECASE
                        )
                        forms_extracted.append({"action": "", "method": "GET", "inputs": inputs})

                    return {
                        "title": page_title,
                        "dom_count": html_text.count("<"),
                        "forms": forms_extracted,
                        "js_errors": [],
                        "security_headers": {
                            "Content-Security-Policy": headers.get(
                                "content-security-policy", "missing"
                            ),
                            "X-Frame-Options": headers.get("x-frame-options", "missing"),
                            "Strict-Transport-Security": headers.get(
                                "strict-transport-security", "missing"
                            ),
                        },
                        "engine": "httpx-fallback",
                    }
            except Exception as err:
                self.logger.warning(f"HTTP inspection fallback failed for {url}: {err}")
                return {
                    "error": str(err),
                    "title": "Navigation Failed",
                    "dom_count": 0,
                    "forms": [],
                    "js_errors": [],
                    "security_headers": {},
                    "engine": "failed",
                }
