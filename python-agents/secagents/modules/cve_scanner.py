"""CVE exploitation scanner: multi-phase pipeline with deterministic checks."""

from __future__ import annotations

import asyncio
import hashlib
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from dataclasses import dataclass, field

import httpx

from secagents.modules.cve_checks import (
    CheckDefinition,
    CheckResult,
    build_payloads,
    get_checks_for_url,
    verify_finding,
)
from secagents.modules.external_tools import ExternalTools
from secagents.infra.logging_system import AuditLogger, AuditCategory
from secagents.infra.scope import enforce_scope, ScopeViolationError
from secagents.infra.execution_budget import ExecutionBudget, BudgetExceeded
from secagents.core.aura_memory import AuraMemoryManager
from secagents.operational.fuzzing import payload_variants


@dataclass
class ScanConfig:
    target: str
    threads: int = 10
    timeout: int = 10
    checks: list[str] | None = None  # None = all checks
    verify_ssl: bool = True
    seed_urls: list[str] | None = None
    allow_stateful_requests: bool = False
    budget: ExecutionBudget | None = None
    auth_headers: dict[str, str] | None = None
    fuzz_payloads: bool = False
    max_payload_variants: int = 6
    fuzz_cooldown_seconds: float = 86400.0
    fuzz_memory: AuraMemoryManager | None = None


@dataclass
class ScanProgress:
    total_urls: int = 0
    candidate_urls: int = 0
    urls_truncated: int = 0
    processed: int = 0
    findings: list[CheckResult] = field(default_factory=list)
    skipped_stateful_checks: int = 0
    skipped_callback_checks: int = 0
    fuzz_variants_generated: int = 0
    fuzz_variants_sent: int = 0
    fuzz_variants_repeated: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


class CVEScanner:
    """5-phase exploitation pipeline inspired by TerminatorZ."""

    def __init__(self, config: ScanConfig):
        if config.fuzz_payloads and config.budget is None:
            raise ValueError("Payload fuzzing requires a shared execution budget")
        if not 0 <= config.max_payload_variants <= 32 or config.fuzz_cooldown_seconds < 0:
            raise ValueError("Invalid payload fuzzing limits")
        self.config = config
        self.progress = ScanProgress()
        self._logger = AuditLogger.get_instance()
        self._sem = asyncio.Semaphore(config.threads)

    async def _request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs):
        if self.config.budget is not None:
            async with self.config.budget.request(url):
                return await client.request(method, url, **kwargs)
        enforce_scope(url)
        return await client.request(method, url, **kwargs)

    async def run(self) -> ScanProgress:
        """Execute full 5-phase pipeline: Recon → Validate → Gate → Attack → Report."""
        self._logger.audit(AuditCategory.SCAN_START, f"CVE scan: {self.config.target}")

        # Phase 1: Reconnaissance
        urls = await self._phase_recon()
        self.progress.candidate_urls = len(urls)
        self.progress.urls_truncated = max(0, len(urls) - 500)

        # Phase 2: Validation (alive check)
        alive_urls = await self._phase_validate(urls)
        self.progress.total_urls = len(alive_urls)

        if not alive_urls:
            return self.progress

        # Phase 3: Confirmation gate (in API mode, auto-proceed)
        # Phase 4: Attack
        await self._phase_attack(alive_urls)

        # Phase 5: Results ready for reporting
        self._logger.audit(
            AuditCategory.SCAN_COMPLETE,
            f"CVE scan complete: {len(self.progress.findings)} findings from {self.progress.processed} URLs",
        )
        return self.progress

    async def _phase_recon(self) -> list[str]:
        """Multi-source recon: subfinder + waybackurls."""
        root = self.config.target
        urls = {root if root.startswith(("http://", "https://")) else f"https://{root}/"}
        enforce_scope(next(iter(urls)))
        for seed in self.config.seed_urls or []:
            try:
                enforce_scope(seed)
                urls.add(seed)
            except ScopeViolationError:
                continue

        # Subdomain discovery
        result = await ExternalTools.run(
            "subfinder", self.config.target, timeout=60, budget=self.config.budget
        )
        if result.success:
            for sub in result.output:
                try:
                    enforce_scope(f"https://{sub}/")
                    urls.add(f"https://{sub}/")
                    urls.add(f"http://{sub}/")
                except ScopeViolationError:
                    continue

        # Wayback URLs
        result = await ExternalTools.run(
            "waybackurls", self.config.target, timeout=60, budget=self.config.budget
        )
        if result.success:
            for u in result.output:
                if u.startswith("http"):
                    try:
                        enforce_scope(u)
                        urls.add(u)
                    except ScopeViolationError:
                        continue

        # Sanitize: drop malformed, too-long, non-http
        sanitized = []
        for u in urls:
            if len(u) <= 2000 and u.startswith("http") and " " not in u:
                sanitized.append(u)

        return sorted(sanitized)

    async def _phase_validate(self, urls: list[str]) -> list[str]:
        """Validate the scoped URL inventory with a bounded HTTP client."""
        alive = []
        async with httpx.AsyncClient(
            verify=self.config.verify_ssl,
            timeout=self.config.timeout,
            follow_redirects=False,
            headers=self.config.auth_headers or {},
        ) as client:
            sem = asyncio.Semaphore(self.config.threads * 2)

            async def probe(url: str):
                async with sem:
                    try:
                        resp = await self._request(client, "HEAD", url)
                        if resp.status_code in (405, 501):
                            resp = await self._request(client, "GET", url)
                        if resp.status_code < 500 and resp.status_code not in (
                            301,
                            302,
                            303,
                            307,
                            308,
                        ):
                            alive.append(url)
                    except Exception:
                        pass

            await asyncio.gather(*[probe(u) for u in sorted(urls)[:500]])
        return alive

    async def _phase_attack(self, urls: list[str]) -> None:
        """Run checks against all alive URLs with worker pool and shared client."""
        async with httpx.AsyncClient(
            verify=self.config.verify_ssl,
            timeout=self.config.timeout,
            follow_redirects=False,
            headers=self.config.auth_headers or {},
        ) as client:
            tasks = [self._scan_url(client, url) for url in urls]
            await asyncio.gather(*tasks)

    async def _scan_url(self, client: httpx.AsyncClient, url: str) -> None:
        """Run appropriate checks against a single URL using shared client."""
        async with self._sem:
            checks = get_checks_for_url(url)

            # Filter to selected checks if custom scan
            if self.config.checks:
                checks = [c for c in checks if c.key in self.config.checks]

            for check in checks:
                if self.config.budget and self.config.budget.snapshot()["termination_reason"]:
                    break
                result = await self._run_check(client, url, check)
                if result and result.vulnerable:
                    self.progress.findings.append(result)

            self.progress.processed += 1

    async def _run_check(
        self, client: httpx.AsyncClient, url: str, check: CheckDefinition
    ) -> CheckResult | None:
        """Execute a single deterministic check."""
        payloads = build_payloads(check.key, url)
        if self.config.fuzz_payloads:
            expanded = []
            feedback = (
                self.config.fuzz_memory.recall_fuzz_feedback(
                    hashlib.sha256(url.encode()).hexdigest(), check.key
                )
                if self.config.fuzz_memory is not None
                else {}
            )
            for payload in payloads:
                expanded.append(payload)
                variants = payload_variants(check.key, payload, 32)
                variants.sort(
                    key=lambda item: (
                        (feedback.get(item["mutation_name"], (0, 0))[1] + 1)
                        / (feedback.get(item["mutation_name"], (0, 0))[0] + 2)
                    ),
                    reverse=True,
                )
                expanded.extend(variants[: self.config.max_payload_variants])
            self.progress.fuzz_variants_generated += len(expanded) - len(payloads)
            payloads = expanded

        if not payloads and not check.header_only:
            self.progress.skipped_callback_checks += 1
            return None

        if not payloads:
            # Header-only checks: just fetch the URL
            try:
                resp = await self._request(client, "GET", url)
                if resp.status_code >= 400 or resp.is_redirect:
                    return None
                headers = {k.lower(): v for k, v in resp.headers.items()}
                vulnerable, proof = verify_finding(check.key, resp.text, headers, {})
                if vulnerable:
                    return CheckResult(
                        name=check.name,
                        severity=check.severity,
                        vulnerable=True,
                        target_url=url,
                        poc_url=url,
                        proof_signal=proof,
                        check_key=check.key,
                        request_method="GET",
                        payload_spec={},
                    )
            except Exception:
                pass
            return None

        # Payload-based checks
        for payload in payloads:
            if payload.get("method") == "POST" and not self.config.allow_stateful_requests:
                self.progress.skipped_stateful_checks += 1
                continue
            variant_fingerprint = ""
            memory_target = ""
            if payload.get("mutation_name"):
                variant_fingerprint = hashlib.sha256(
                    f"{check.key}|{payload.get('param')}|{payload.get('value')}".encode()
                ).hexdigest()
                memory_target = hashlib.sha256(url.encode()).hexdigest()
                memory = self.config.fuzz_memory
                if memory is not None and not memory.claim_fuzz_attempt(
                    memory_target,
                    check.key,
                    variant_fingerprint,
                    retry_after_seconds=self.config.fuzz_cooldown_seconds,
                ):
                    self.progress.fuzz_variants_repeated += 1
                    continue
                payload["mutation_fingerprint"] = variant_fingerprint
            try:
                poc_url = url
                if payload.get("method") == "HEADER":
                    headers = {payload["header"]: payload["value"]}
                    resp = await self._request(client, "GET", url, headers=headers)
                elif payload.get("method") == "POST":
                    data = {payload["param"]: payload["value"]}
                    resp = await self._request(client, "POST", url, data=data)
                elif payload.get("method") == "GET_PATH":
                    parts = urlsplit(url)
                    poc_url = urlunsplit((parts.scheme, parts.netloc, payload["path"], "", ""))
                    resp = await self._request(client, "GET", poc_url)
                    if resp.status_code != 200:
                        continue
                else:
                    parts = urlsplit(url)
                    params = parse_qsl(parts.query, keep_blank_values=True)
                    params = [(name, value) for name, value in params if name != payload["param"]]
                    params.append((payload["param"], payload["value"]))
                    poc_url = urlunsplit(
                        (parts.scheme, parts.netloc, parts.path, urlencode(params), "")
                    )
                    resp = await self._request(client, "GET", poc_url)

                if variant_fingerprint:
                    self.progress.fuzz_variants_sent += 1

                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                vulnerable, proof = verify_finding(check.key, resp.text, resp_headers, payload)
                if variant_fingerprint and self.config.fuzz_memory is not None:
                    self.config.fuzz_memory.record_fuzz_outcome(
                        memory_target,
                        check.key,
                        variant_fingerprint,
                        "candidate" if vulnerable else "no_signal",
                    )
                    if not vulnerable:
                        self.config.fuzz_memory.record_fuzz_feedback(
                            memory_target, check.key, payload["mutation_name"], False
                        )

                if vulnerable:
                    return CheckResult(
                        name=check.name,
                        severity=check.severity,
                        vulnerable=True,
                        target_url=url,
                        poc_url=poc_url,
                        proof_signal=proof,
                        check_key=check.key,
                        request_method="POST" if payload.get("method") == "POST" else "GET",
                        request_headers=headers if payload.get("method") == "HEADER" else None,
                        request_data=data if payload.get("method") == "POST" else None,
                        payload_spec=payload,
                    )
            except BudgetExceeded:
                if variant_fingerprint and self.config.fuzz_memory is not None:
                    self.config.fuzz_memory.release_fuzz_attempt(
                        memory_target, check.key, variant_fingerprint
                    )
                break
            except Exception:
                if variant_fingerprint and self.config.fuzz_memory is not None:
                    self.config.fuzz_memory.release_fuzz_attempt(
                        memory_target, check.key, variant_fingerprint
                    )
                continue

        return None
