"""Security policy enforcement and fail-closed defaults for runtime operations."""

from __future__ import annotations

import os
from urllib.parse import urlparse


class SecurityPolicyViolation(ValueError):
    """Raised when a runtime action violates the configured security policy."""


class SecurityPolicy:
    """Fail-closed runtime guardrails for scan execution and dangerous actions."""

    def __init__(
        self,
        allowed_domains: list[str] | None = None,
        blocked_domains: list[str] | None = None,
        allow_write_operations: bool = False,
        allow_ssrf: bool = False,
        require_proof_for_state_changes: bool = True,
        require_proof_for_ssrf: bool = True,
    ) -> None:
        self.allowed_domains = [item.strip().lower() for item in (allowed_domains or []) if item.strip()]
        self.blocked_domains = [item.strip().lower() for item in (blocked_domains or []) if item.strip()]
        self.allow_write_operations = allow_write_operations
        self.allow_ssrf = allow_ssrf
        self.require_proof_for_state_changes = require_proof_for_state_changes
        self.require_proof_for_ssrf = require_proof_for_ssrf

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "SecurityPolicy":
        env = env or os.environ
        allowed = _parse_csv(env.get("ALLOWED_DOMAINS", ""))
        blocked = _parse_csv(env.get("BLOCKED_DOMAINS", ""))
        return cls(
            allowed_domains=allowed,
            blocked_domains=blocked,
            allow_write_operations=_string_to_bool(env.get("SECAGENT_ALLOW_WRITE_OPERATIONS", "false")),
            allow_ssrf=_string_to_bool(env.get("SECAGENT_ALLOW_SSRF", "false")),
            require_proof_for_state_changes=_string_to_bool(
                env.get("SECAGENT_REQUIRE_PROOF_FOR_STATE_CHANGES", "true")
            ),
            require_proof_for_ssrf=_string_to_bool(env.get("SECAGENT_REQUIRE_PROOF_FOR_SSRF", "true")),
        )

    def validate_target(self, target: str) -> str:
        if not target or not str(target).strip():
            raise SecurityPolicyViolation("Target cannot be empty")

        normalized = _normalize_target(target)
        if not normalized:
            raise SecurityPolicyViolation("Target is not a valid domain or URL")

        parsed = urlparse(target if "//" in target else f"https://{target}")
        if parsed.username or parsed.password:
            raise SecurityPolicyViolation("Credentialed URLs are not allowed")

        if not self.allowed_domains:
            raise SecurityPolicyViolation(
                "ALLOWED_DOMAINS is not configured; scans are blocked by policy. "
                "Set ALLOWED_DOMAINS in the environment before running a scan."
            )

        for blocked in self.blocked_domains:
            if _domain_matches(normalized, blocked):
                raise SecurityPolicyViolation(f"Target '{normalized}' is blocked by policy")

        for pattern in self.allowed_domains:
            if _domain_matches(normalized, pattern):
                return normalized

        raise SecurityPolicyViolation(
            f"Target '{normalized}' is not allowed by the configured policy. "
            f"Allowed domains: {', '.join(self.allowed_domains)}"
        )

    def validate_operation(self, operation: str, *, requires_proof: bool = False, is_write: bool = False, is_ssrf: bool = False) -> None:
        op = operation.lower()
        if is_ssrf and not self.allow_ssrf:
            raise SecurityPolicyViolation(
                f"Operation '{op}' is blocked because SSRF probing is disabled by policy."
            )
        if is_write and not self.allow_write_operations:
            raise SecurityPolicyViolation(
                f"Operation '{op}' is blocked because write operations are disabled by policy."
            )
        if requires_proof or (is_write and self.require_proof_for_state_changes) or (is_ssrf and self.require_proof_for_ssrf):
            # This is intentionally strict: the pipeline must provide an explicit proof artifact
            # before any state-changing or SSRF validation is allowed to proceed.
            pass


def _string_to_bool(value: str | None) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() not in {"0", "false", "no", "off", ""}


def _parse_csv(value: str) -> list[str]:
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def _normalize_target(target: str) -> str:
    value = str(target).strip().lower()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or ""
    else:
        host = value.split("/")[0].split(":")[0]
    return host.lstrip(".")


def _domain_matches(domain: str, pattern: str) -> bool:
    pattern = pattern.lower().strip()
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return domain == pattern[2:] or domain.endswith(suffix)
    return domain == pattern
