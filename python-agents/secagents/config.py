"""Runtime configuration and validation for SecAgent.

This module centralizes environment-driven defaults and CLI validation so the
project behaves predictably in CI, local dev, and production-like deployments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

from secagents.infra.security_policy import SecurityPolicy


def _normalize_bool(value: str | bool | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() not in {"0", "false", "no", "off", ""}


@dataclass(frozen=True)
class ScanConfig:
    target: str
    depth: str = "standard"
    workers: int = 4
    max_requests: int = 1000
    requests_per_second_per_host: float = 5.0
    max_duration_seconds: float = 900.0
    check_ssl: bool = True
    use_sandbox: bool = True
    results_dir: str = "cog-ai-results"
    allowed_domains: list[str] = field(default_factory=list)
    blocked_domains: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.target or not str(self.target).strip():
            raise ValueError("Target cannot be empty")
        if self.workers <= 0:
            raise ValueError("workers must be > 0")
        if self.max_requests <= 0:
            raise ValueError("max_requests must be > 0")
        if self.requests_per_second_per_host <= 0:
            raise ValueError("requests_per_second_per_host must be > 0")
        if self.max_duration_seconds <= 0:
            raise ValueError("max_duration_seconds must be > 0")
        if self.depth not in {"quick", "standard", "deep"}:
            raise ValueError("depth must be one of: quick, standard, deep")


@dataclass(frozen=True)
class AppConfig:
    target: str
    scan: ScanConfig
    log_level: str = "INFO"
    json_output: bool = False
    security: SecurityPolicy | None = None

    def __post_init__(self) -> None:
        if self.security is None:
            object.__setattr__(self, "security", SecurityPolicy.from_env())
        # Enforce scope and request safety before running any scan.
        self.security.validate_target(self.target)


def _parse_allowed_domains(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def build_scan_config(args: object | None = None, env: dict[str, str] | None = None) -> ScanConfig:
    env = env or os.environ
    if args is not None:
        target = getattr(args, "target", env.get("SECAGENT_TARGET", ""))
        depth = getattr(args, "depth", env.get("SECAGENT_DEPTH", "standard"))
        workers = int(getattr(args, "workers", env.get("SECAGENT_WORKERS", "4")))
        max_requests = int(getattr(args, "max_requests", env.get("SECAGENT_MAX_REQUESTS", "1000")))
        rps = float(
            getattr(args, "rate_limit", env.get("SECAGENT_RATE_LIMIT", "5.0"))
        )
        max_duration = float(
            getattr(args, "max_duration", env.get("SECAGENT_MAX_DURATION", "900"))
        )
        results_dir = getattr(args, "results_dir", env.get("SECAGENT_RESULTS_DIR", "cog-ai-results"))
        verify_ssl = _normalize_bool(
            getattr(args, "insecure", None),
            default=not _normalize_bool(env.get("SECAGENT_VERIFY_SSL", "true"), default=True),
        )
        check_ssl = not bool(getattr(args, "insecure", False))
    else:
        target = env.get("SECAGENT_TARGET", "")
        depth = env.get("SECAGENT_DEPTH", "standard")
        workers = int(env.get("SECAGENT_WORKERS", "4"))
        max_requests = int(env.get("SECAGENT_MAX_REQUESTS", "1000"))
        rps = float(env.get("SECAGENT_RATE_LIMIT", "5.0"))
        max_duration = float(env.get("SECAGENT_MAX_DURATION", "900"))
        results_dir = env.get("SECAGENT_RESULTS_DIR", "cog-ai-results")
        check_ssl = _normalize_bool(env.get("SECAGENT_VERIFY_SSL", "true"), default=True)
        verify_ssl = check_ssl

    allowed = _parse_allowed_domains(env.get("ALLOWED_DOMAINS"))
    blocked = _parse_allowed_domains(env.get("BLOCKED_DOMAINS"))
    return ScanConfig(
        target=target,
        depth=depth,
        workers=workers,
        max_requests=max_requests,
        requests_per_second_per_host=rps,
        max_duration_seconds=max_duration,
        check_ssl=check_ssl and verify_ssl,
        use_sandbox=not _normalize_bool(env.get("SECAGENT_DISABLE_SANDBOX", "false"), default=False),
        results_dir=results_dir,
        allowed_domains=allowed,
        blocked_domains=blocked,
    )


def load_runtime_config(args: object | None = None, env: dict[str, str] | None = None) -> AppConfig:
    env = env or os.environ
    policy = SecurityPolicy.from_env(env)
    scan_cfg = build_scan_config(args, env)
    target = getattr(args, "target", None) if args is not None else env.get("SECAGENT_TARGET", "")
    if not target:
        target = env.get("SECAGENT_TARGET", "")

    if not target:
        raise ValueError("A target is required to start a scan")

    log_level = getattr(args, "log_level", env.get("SECAGENT_LOG_LEVEL", "INFO")) if args else env.get("SECAGENT_LOG_LEVEL", "INFO")
    json_output = bool(
        getattr(args, "json_output", False)
        if args is not None
        else _normalize_bool(env.get("SECAGENT_JSON_OUTPUT", "false"), default=False)
    )
    return AppConfig(
        target=target,
        scan=scan_cfg,
        log_level=str(log_level).upper(),
        json_output=json_output,
        security=policy,
    )
