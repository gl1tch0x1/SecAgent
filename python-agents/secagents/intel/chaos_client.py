"""Module 10: Project Discovery Chaos API for subdomain enumeration."""

from __future__ import annotations

import os

import httpx

from secagents.infra.scope import enforce_scope, ScopeViolationError
from secagents.infra.execution_budget import ExecutionBudget


class ChaosIntel:
    def __init__(self, api_key: str | None = None, budget: ExecutionBudget | None = None):
        self.api_key = api_key or os.environ.get("CHAOS_API_KEY", "")
        self.budget = budget

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    async def subdomains(self, domain: str) -> list[str]:
        if not self.available:
            return []
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
            if self.budget:
                async with self.budget.provider_request(url):
                    resp = await client.get(url, headers={"Authorization": self.api_key})
            else:
                resp = await client.get(url, headers={"Authorization": self.api_key})
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    subdomains = data
                else:
                    subdomains = data.get("subdomains", data.get("results", []))

                # Filter subdomains against ALLOWED_DOMAINS
                scoped_subdomains = []
                for sub in subdomains:
                    try:
                        enforce_scope(sub)
                        scoped_subdomains.append(sub)
                    except ScopeViolationError:
                        continue
                return scoped_subdomains
        return []
