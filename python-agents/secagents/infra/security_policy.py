"""Security policy enforcement and fail-closed defaults for runtime operations."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

from secagents.infra.audit import AuditLogger


class SecurityPolicyViolation(ValueError):
    """Raised when a runtime action violates the configured security policy."""


@dataclass(frozen=True)
class OperationAuthorization:
    """An explicit operator contract bound to one action and target."""

    kind: str
    operation: str
    target: str


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
        audit_path: str | None = None,
    ) -> None:
        self.allowed_domains = [
            item.strip().lower() for item in (allowed_domains or []) if item.strip()
        ]
        self.blocked_domains = [
            item.strip().lower() for item in (blocked_domains or []) if item.strip()
        ]
        self.allow_write_operations = allow_write_operations
        self.allow_ssrf = allow_ssrf
        self.require_proof_for_state_changes = require_proof_for_state_changes
        self.require_proof_for_ssrf = require_proof_for_ssrf
        self.audit_logger = AuditLogger(audit_path) if audit_path else AuditLogger()

    @classmethod
    def from_env(
        cls,
        env: dict[str, str] | None = None,
        *,
        contracted_write: bool = False,
        contracted_ssrf: bool = False,
    ) -> "SecurityPolicy":
        if env is None:
            env = dict(os.environ)
        allowed = _parse_csv(env.get("ALLOWED_DOMAINS", ""))
        blocked = _parse_csv(env.get("BLOCKED_DOMAINS", ""))
        audit_path = env.get("SECAGENT_AUDIT_LOG_PATH")
        return cls(
            allowed_domains=allowed,
            blocked_domains=blocked,
            allow_write_operations=contracted_write
            or _string_to_bool(env.get("SECAGENT_ALLOW_WRITE_OPERATIONS", "false")),
            allow_ssrf=contracted_ssrf or _string_to_bool(env.get("SECAGENT_ALLOW_SSRF", "false")),
            require_proof_for_state_changes=_string_to_bool(
                env.get("SECAGENT_REQUIRE_PROOF_FOR_STATE_CHANGES", "true")
            ),
            require_proof_for_ssrf=_string_to_bool(
                env.get("SECAGENT_REQUIRE_PROOF_FOR_SSRF", "true")
            ),
            audit_path=audit_path,
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
                "No authorized target scope is configured. Run 'secagent scope --add DOMAIN' "
                "or pass --authorize-targets for this scan."
            )

        for blocked in self.blocked_domains:
            if _domain_matches(normalized, blocked):
                raise SecurityPolicyViolation(f"Target '{normalized}' is blocked by policy")

        for pattern in self.allowed_domains:
            if _domain_matches(normalized, pattern):
                return normalized

        raise SecurityPolicyViolation(
            f"Target '{normalized}' is not allowed by the configured policy. "
            f"Allowed domains: {', '.join(self.allowed_domains)}. "
            f"Run 'secagent scope --add {normalized}' or pass --authorize-targets."
        )

    def validate_operation(
        self,
        operation: str,
        *,
        requires_proof: bool = False,
        is_write: bool = False,
        is_ssrf: bool = False,
        proof_artifact: object | None = None,
        target: str | None = None,
    ) -> None:
        op = operation.lower()
        if is_ssrf and not self.allow_ssrf:
            self.audit_logger.record_decision(
                operation=op,
                allowed=False,
                reason="SSRF probing is disabled by policy",
                event="ssrf_blocked",
                is_ssrf=True,
            )
            raise SecurityPolicyViolation(
                f"Operation '{op}' is blocked because SSRF probing is disabled by policy."
            )
        if is_write and not self.allow_write_operations:
            self.audit_logger.record_decision(
                operation=op,
                allowed=False,
                reason="Write operations are disabled by policy",
                event="write_blocked",
                is_write=True,
            )
            raise SecurityPolicyViolation(
                f"Operation '{op}' is blocked because write operations are disabled by policy."
            )

        requires_proof = bool(requires_proof or is_write or is_ssrf)

        expected_kind = "state_contract" if is_write else "ssrf_contract" if is_ssrf else None
        authorized = (
            isinstance(proof_artifact, OperationAuthorization)
            and bool(target)
            and proof_artifact.operation == op
            and proof_artifact.target == target
            and (expected_kind is None or proof_artifact.kind == expected_kind)
        )
        if requires_proof and not authorized:
            self.audit_logger.record_decision(
                operation=op,
                allowed=False,
                reason="Missing proof artifact for sensitive runtime action",
                event="proof_required",
                requires_proof=True,
                is_write=is_write,
                is_ssrf=is_ssrf,
            )
            raise SecurityPolicyViolation(
                f"Operation '{op}' requires a proof artifact before execution. "
                "Provide explicit validation evidence or a signed proof record."
            )

        self.audit_logger.record_decision(
            operation=op,
            allowed=True,
            reason="Policy checks passed",
            event="policy_approved",
            requires_proof=requires_proof,
            is_write=is_write,
            is_ssrf=is_ssrf,
            has_authorization=authorized,
        )


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
