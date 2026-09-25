"""Module 10: Shodan integration for recon phase."""

from __future__ import annotations

import os

import httpx

from secagents.infra.scope import enforce_scope, ScopeViolationError
from secagents.infra.execution_budget import ExecutionBudget


class ShodanIntel:
    def __init__(self, api_key: str | None = None, budget: ExecutionBudget | None = None):
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY", "")
        self.budget = budget

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    async def host_info(self, ip: str) -> dict:
        if not self.available:
            return {}
        async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
            url = f"https://api.shodan.io/shodan/host/{ip}"
            if self.budget:
                async with self.budget.provider_request(url):
                    resp = await client.get(url, params={"key": self.api_key})
            else:
                resp = await client.get(url, params={"key": self.api_key})
            if resp.status_code == 200:
                return resp.json()
        return {}

    async def search_domain(self, domain: str) -> list[dict]:
        if not self.available:
            return []
        async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
            url = "https://api.shodan.io/dns/domain/" + domain
            if self.budget:
                async with self.budget.provider_request(url):
                    resp = await client.get(url, params={"key": self.api_key})
            else:
                resp = await client.get(url, params={"key": self.api_key})
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("data", [])

                # Filter domains against ALLOWED_DOMAINS
                scoped_results = []
                for record in results:
                    domain_name = record.get("domain", "")
                    if domain_name:
                        try:
                            enforce_scope(domain_name)
                            scoped_results.append(record)
                        except ScopeViolationError:
                            continue
                return scoped_results
        return []

    async def cves_for_host(self, ip: str) -> list[str]:
        info = await self.host_info(ip)
        vulns = info.get("vulns", [])
        return list(vulns) if isinstance(vulns, list) else []
