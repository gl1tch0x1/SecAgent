"""Portable Proof Capsule serialization and single-vulnerability replay engine."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
from secagents.infra.scope import enforce_scope
from secagents.infra.execution_budget import BudgetExceeded, ExecutionBudget
from secagents.modules.cve_checks import verify_finding
import os
from secagents.remediation.reporter import _redact

logger = logging.getLogger("secagents.proof_capsule")


@dataclass
class ProofCapsule:
    id: str
    target_url: str
    vuln_type: str
    title: str
    severity: str
    http_method: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    query_params: Dict[str, str]
    proof_signal: str
    timestamp: float
    metadata: Dict[str, Any]

    def to_json(self) -> str:
        data = _redact(asdict(self))
        # Capsules can be shared. Only headers with no credential semantics are
        # portable; authenticated replay can read them from named environment
        # variables via metadata.request_header_env.
        public_headers = {"accept", "content-type", "user-agent"}
        data["request_headers"] = {
            key: value if key.lower() in public_headers else "[REDACTED]"
            for key, value in data["request_headers"].items()
        }
        if data["request_body"] is not None:
            data["request_body"] = "[REDACTED]"
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> ProofCapsule:
        data = json.loads(json_str)
        return cls(**data)

    def save(self, filepath: Path) -> Path:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(self.to_json(), encoding="utf-8")
        logger.info(f"Saved proof capsule {self.id} to {filepath}")
        return filepath


class ProofCapsuleReplayer:
    """Zero-dependency replay engine for SecAgent proof capsules."""

    def __init__(
        self,
        timeout_seconds: float = 10.0,
        budget: ExecutionBudget | None = None,
    ):
        self.timeout = timeout_seconds
        self.budget = budget or ExecutionBudget(
            max_requests=10, max_duration_seconds=30, max_concurrency=2
        )

    async def replay_async(self, capsule: ProofCapsule) -> tuple[bool, str]:
        """Replay proof capsule HTTP request and check if target remains vulnerable."""
        try:
            enforce_scope(capsule.target_url)
            check_key = capsule.metadata.get("check_key", "")
            if not check_key:
                return False, "[INCONCLUSIVE] Capsule has no typed proof policy"
            from secagents.crucible.validation import MANUAL_PROOF_CHECKS
            from secagents.crucible.proof_policy import PROOF_POLICIES

            if check_key in MANUAL_PROOF_CHECKS:
                return False, f"[INCONCLUSIVE] {check_key} requires additional proof"
            policy = PROOF_POLICIES.get(check_key)
            if policy is None:
                return False, "[INCONCLUSIVE] No registered proof policy"
            method = capsule.http_method.upper()
            if method != "GET":
                return False, "[INCONCLUSIVE] Write replay requires a state and cleanup policy"
            verify_ssl = os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false"
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=False, verify=verify_ssl
            ) as client:
                method = capsule.http_method.upper()
                headers = {
                    key: value
                    for key, value in (capsule.request_headers or {}).items()
                    if value != "[REDACTED]"
                }
                header_env = capsule.metadata.get("request_header_env", {})
                if not isinstance(header_env, dict):
                    return False, "[INCONCLUSIVE] Invalid request_header_env mapping"
                for header, env_name in header_env.items():
                    if not isinstance(header, str) or not isinstance(env_name, str):
                        return False, "[INCONCLUSIVE] Invalid credential environment reference"
                    secret = os.environ.get(env_name)
                    if not secret:
                        return (
                            False,
                            f"[INCONCLUSIVE] Missing credential environment variable: {env_name}",
                        )
                    headers[header] = secret
                if any(
                    value == "[REDACTED]" and key not in header_env
                    for key, value in (capsule.request_headers or {}).items()
                ):
                    return (
                        False,
                        "[INCONCLUSIVE] Capsule requires credential environment references",
                    )
                params = capsule.query_params or {}
                if "[REDACTED]" in capsule.target_url or "[REDACTED]" in params.values():
                    return False, "[INCONCLUSIVE] Capsule contains redacted request parameters"
                if capsule.request_body == "[REDACTED]":
                    return False, "[INCONCLUSIVE] Capsule contains a redacted request body"
                payload_spec = capsule.metadata.get("payload_spec") or {}
                if policy.negative_control and not payload_spec:
                    return False, "[INCONCLUSIVE] Active capsule lacks a replayable payload"
                async with self.budget.request(capsule.target_url):
                    resp = await client.request(
                        method,
                        capsule.target_url,
                        headers=headers,
                        params=params,
                        content=capsule.request_body,
                    )
                response_headers = {k.lower(): v for k, v in resp.headers.items()}
                if 300 <= resp.status_code < 500:
                    return (
                        False,
                        "[INCONCLUSIVE] Redirect or client-error response cannot establish proof",
                    )
                if not policy.negative_control and resp.status_code >= 500:
                    return (
                        False,
                        "[INCONCLUSIVE] Server-error response cannot establish passive proof",
                    )
                is_vulnerable, signal = verify_finding(
                    check_key,
                    resp.text[:100_000],
                    response_headers,
                    payload_spec,
                )
                if is_vulnerable and policy.negative_control:
                    base_url = capsule.metadata.get("base_url")
                    if not base_url:
                        return False, "[INCONCLUSIVE] Active capsule lacks a control URL"
                    if "[REDACTED]" in base_url:
                        return False, "[INCONCLUSIVE] Capsule contains a redacted control URL"
                    enforce_scope(base_url)
                    if method == "GET":
                        async with self.budget.request(base_url):
                            control = await client.get(base_url, headers=headers)
                    else:
                        return (
                            False,
                            "[INCONCLUSIVE] Active write replay requires a state-safe control",
                        )
                    control_headers = {k.lower(): v for k, v in control.headers.items()}
                    control_positive, _ = verify_finding(
                        check_key, control.text[:100_000], control_headers, payload_spec
                    )
                    if control_positive:
                        return False, "[INCONCLUSIVE] Proof condition also appears in control"
                    for _ in range(policy.minimum_positive_runs - 1):
                        async with self.budget.request(capsule.target_url):
                            replay = await client.request(
                                method,
                                capsule.target_url,
                                headers=headers,
                                params=params,
                                content=capsule.request_body,
                            )
                        replay_positive, _ = verify_finding(
                            check_key,
                            replay.text[:100_000],
                            {k.lower(): v for k, v in replay.headers.items()},
                            payload_spec,
                        )
                        if not replay_positive or replay.status_code != resp.status_code:
                            return (
                                False,
                                "[INCONCLUSIVE] Independent replay did not reproduce proof",
                            )
                status_msg = (
                    f"[VERIFIED] Proof policy '{check_key}' reproduced (HTTP {resp.status_code})"
                    if is_vulnerable
                    else f"[INCONCLUSIVE] Proof policy '{check_key}' did not reproduce (HTTP {resp.status_code}): {signal}"
                )
                return is_vulnerable, status_msg
        except (httpx.HTTPError, PermissionError, ValueError, BudgetExceeded) as e:
            return False, f"[REPLAY ERROR] {e}"

    def replay_file(self, capsule_path: Path) -> tuple[bool, str]:
        """Synchronous helper to read capsule file and replay."""
        import asyncio

        capsule = ProofCapsule.from_json(capsule_path.read_text(encoding="utf-8"))
        return asyncio.run(self.replay_async(capsule))
