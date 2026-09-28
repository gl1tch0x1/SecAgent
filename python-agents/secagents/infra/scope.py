"""Target scope enforcement via ALLOWED_DOMAINS (fail-closed)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


class ScopeViolationError(PermissionError):
    """Raised when a target is outside authorized scope."""


@dataclass
class ScopePolicy:
    allowed_domains: list[str]
    blocked_domains: list[str]

    @classmethod
    def from_env(cls) -> ScopePolicy:
        allowed = _parse_list(os.environ.get("ALLOWED_DOMAINS", ""))
        blocked = _parse_list(os.environ.get("BLOCKED_DOMAINS", ""))
        return cls(allowed_domains=allowed, blocked_domains=blocked)

    def check_target(self, target: str) -> None:
        if "://" in target:
            parsed = urlparse(target)
            if parsed.scheme.lower() not in {"http", "https"} or parsed.username or parsed.password:
                raise ScopeViolationError("Only credential-free HTTP(S) targets are allowed")
        domain = normalize_target(target)
        if not domain:
            raise ScopeViolationError("Invalid or empty target")

        for blocked in self.blocked_domains:
            if _domain_matches(domain, blocked):
                raise ScopeViolationError(f"Target '{domain}' is blocked by BLOCKED_DOMAINS")

        if not self.allowed_domains:
            raise ScopeViolationError(
                "ALLOWED_DOMAINS is not configured. Set it in .env before scanning "
                "(e.g. ALLOWED_DOMAINS=example.com,*.example.com)"
            )

        for allowed in self.allowed_domains:
            if _domain_matches(domain, allowed):
                return

        raise ScopeViolationError(
            f"Target '{domain}' is not in ALLOWED_DOMAINS: {', '.join(self.allowed_domains)}"
        )


def _parse_list(value: str) -> list[str]:
    return [p.strip().lower() for p in value.split(",") if p.strip()]


def normalize_target(target: str) -> str:
    """Extract registrable host from URL or bare domain."""
    t = target.strip().lower()
    if not t:
        return ""
    if "://" in t:
        parsed = urlparse(t)
        host = parsed.hostname or ""
    else:
        host = t.split("/")[0].split(":")[0]
    return host.lstrip(".")


def _domain_matches(domain: str, pattern: str) -> bool:
    pattern = pattern.lower().strip()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # .example.com
        return domain == pattern[2:] or domain.endswith(suffix)
    return domain == pattern


def enforce_scope(target: str) -> str:
    """Validate target against env policy; return normalized domain."""
    policy = ScopePolicy.from_env()
    policy.check_target(target)
    return normalize_target(target)
