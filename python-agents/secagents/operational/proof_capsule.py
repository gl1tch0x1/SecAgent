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
        return json.dumps(asdict(self), indent=2)

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
                headers = capsule.request_headers or {}
                params = capsule.query_params or {}
                async with self.budget.request(capsule.target_url):
                    resp = await client.request(
                        method,
                        capsule.target_url,
                        headers=headers,
                        params=params,
                        content=capsule.request_body,
                    )
                response_headers = {k.lower(): v for k, v in resp.headers.items()}
                is_vulnerable, signal = verify_finding(
                    check_key,
                    resp.text[:100_000],
                    response_headers,
                    capsule.metadata.get("payload_spec") or {},
                )
                payload_spec = capsule.metadata.get("payload_spec") or {}
                if is_vulnerable and payload_spec:
                    base_url = capsule.metadata.get("base_url")
                    if not base_url:
                        return False, "[INCONCLUSIVE] Active capsule lacks a control URL"
                    enforce_scope(base_url)
                    if method == "GET":
                        async with self.budget.request(base_url):
                            control = await client.get(base_url)
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
