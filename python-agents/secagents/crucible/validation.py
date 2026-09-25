"""Replay scanner observations and publish only findings with typed proof."""

from __future__ import annotations

import os
import hashlib
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from secagents.llm.consensus import ConsensusEngine
from secagents.modules.cve_checks import verify_finding
from secagents.modules.exploit_chain import correlate_chains
from secagents.infra.scope import enforce_scope, ScopeViolationError
from secagents.infra.execution_budget import BudgetExceeded, ExecutionBudget
from secagents.crucible.proof_policy import PROOF_POLICIES
from secagents.crucible.browser_proof import prove_xss


# These checks need browser execution, a second identity, out-of-band evidence,
# or a state read/cleanup contract. A response signature alone cannot prove them.
MANUAL_PROOF_CHECKS = frozenset(
    key for key, policy in PROOF_POLICIES.items() if policy.capability != "http"
)


class CrucibleValidator:
    """Classify candidates as validated, rejected, or requiring manual proof."""

    def __init__(
        self,
        consensus: ConsensusEngine | None = None,
        verify_ssl: bool | None = None,
        budget: ExecutionBudget | None = None,
        auth_headers: dict[str, str] | None = None,
    ):
        self.consensus = consensus
        self.budget = budget
        self.auth_headers = auth_headers or {}
        if verify_ssl is None:
            verify_ssl = os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false"
        self._client = httpx.AsyncClient(
            timeout=20,
            verify=verify_ssl,
            follow_redirects=False,
            headers=self.auth_headers,
        )

    async def _get(self, url: str, **kwargs) -> httpx.Response:
        if self.budget is not None:
            async with self.budget.request(url):
                return await self._client.get(url, **kwargs)
        return await self._client.get(url, **kwargs)

    async def validate_finding(self, finding: dict) -> dict:
        result = dict(finding)
        key = result.get("check_key", "")
        policy = PROOF_POLICIES.get(key)
        if policy is None:
            result.update(
                validated=False,
                validation_status="manual_lead",
                validation_reason="No typed proof policy for this source",
            )
            return result
        if key == "xss":
            url = result.get("poc_url") or result.get("url")
            payload = result.get("payload_spec") or {}
            if not url or not payload:
                result.update(
                    validated=False,
                    validation_status="manual_lead",
                    validation_reason="XSS requires a replayable browser payload",
                )
                return result
            try:
                evidence = await prove_xss(
                    url,
                    payload,
                    self.budget or ExecutionBudget(max_requests=10),
                    self.auth_headers,
                )
            except (ScopeViolationError, ValueError, BudgetExceeded) as exc:
                evidence = {
                    "validated": False,
                    "status": "inconclusive",
                    "reason": str(exc),
                    "observations": [],
                }
            result["proof"] = {
                "policy": key,
                "policy_version": "2.0",
                "evidence_class": policy.evidence_class,
                "observations": evidence.get("observations", []),
            }
            result.update(
                validated=bool(evidence["validated"]),
                validation_status=evidence.get("status", "inconclusive"),
                validation_reason=evidence["reason"],
            )
            return result
        if policy.capability != "http":
            result.update(
                validated=False,
                validation_status="manual_lead",
                validation_reason=f"{key} requires {policy.capability} proof",
            )
            return result

        url = result.get("poc_url") or result.get("url")
        base_url = result.get("url") or url
        if not url or not base_url:
            result.update(
                validated=False, validation_status="inconclusive", validation_reason="No replay URL"
            )
            return result
        try:
            enforce_scope(url)
            enforce_scope(base_url)
            method = result.get("request_method", "GET").upper()
            if method not in {"GET", "POST"}:
                raise ValueError(f"Unsupported replay method: {method}")
            if method == "POST":
                result.update(
                    validated=False,
                    validation_status="manual_lead",
                    validation_reason="POST replay requires a state and cleanup policy",
                )
                return result
            kwargs = {"headers": result.get("request_headers") or {}}
            response = await self._get(url, **kwargs)
            headers = {k.lower(): v for k, v in response.headers.items()}
            payload = result.get("payload_spec") or {}
            if policy.negative_control and not payload:
                result.update(
                    validated=False,
                    validation_status="manual_lead",
                    validation_reason="Active proof policy lacks a replayable payload",
                )
                return result
            proven, signal = verify_finding(key, response.text[:100_000], headers, payload)
            if response.status_code in range(300, 500):
                proven = False
                signal = "Redirect or client-error response cannot establish proof"
            elif not policy.negative_control and response.status_code >= 500:
                proven = False
                signal = "Server-error response cannot establish passive proof"

            observations = [
                {
                    "role": "positive_probe",
                    "status_code": response.status_code,
                    "body_sha256": hashlib.sha256(response.content).hexdigest(),
                }
            ]

            # An unmodified response must not already satisfy an active proof.
            # Passive configuration checks intentionally omit the control.
            if proven and policy.negative_control:
                control_url = base_url
                if payload.get("method") == "GET" and payload.get("param"):
                    parts = urlsplit(url)
                    params = parse_qsl(parts.query, keep_blank_values=True)
                    params = [
                        (name, "secagent_negative_control" if name == payload["param"] else value)
                        for name, value in params
                    ]
                    control_url = urlunsplit(
                        (parts.scheme, parts.netloc, parts.path, urlencode(params), parts.fragment)
                    )
                elif payload.get("method") == "GET_PATH":
                    parts = urlsplit(url)
                    parent = parts.path.rsplit("/", 1)[0]
                    control_url = urlunsplit(
                        (
                            parts.scheme,
                            parts.netloc,
                            parent + "/secagent-negative-control",
                            "",
                            "",
                        )
                    )
                enforce_scope(control_url)
                control = await self._get(control_url, **kwargs)
                control_headers = {k.lower(): v for k, v in control.headers.items()}
                control_positive, _ = verify_finding(
                    key, control.text[:100_000], control_headers, payload
                )
                if control_positive:
                    proven = False
                    signal = "Proof condition also present in unmodified control"
                observations.append(
                    {
                        "role": "negative_control",
                        "status_code": control.status_code,
                        "body_sha256": hashlib.sha256(control.content).hexdigest(),
                    }
                )

            if proven and policy.minimum_positive_runs > 1:
                for _ in range(policy.minimum_positive_runs - 1):
                    replay = await self._get(url, **kwargs)
                    replay_headers = {k.lower(): v for k, v in replay.headers.items()}
                    replay_positive, _ = verify_finding(
                        key, replay.text[:100_000], replay_headers, payload
                    )
                    observations.append(
                        {
                            "role": "positive_replay",
                            "status_code": replay.status_code,
                            "body_sha256": hashlib.sha256(replay.content).hexdigest(),
                        }
                    )
                    if not replay_positive or replay.status_code != response.status_code:
                        proven = False
                        signal = "Independent replay did not reproduce the same proof"
                        break

            result["proof"] = {
                "policy": key,
                "method": method,
                "status_code": response.status_code,
                "signal": signal,
                "control_used": any(
                    observation["role"] == "negative_control" for observation in observations
                ),
                "policy_version": "2.0",
                "evidence_class": policy.evidence_class,
                "minimum_positive_runs": policy.minimum_positive_runs,
                "observations": observations,
            }
            if proven:
                result.update(validated=True, validation_status="validated")
                result["poc"] = {
                    "method": method,
                    "url": url,
                    "request_headers": kwargs["headers"],
                    "request_data": kwargs.get("data", {}),
                    "proof_policy": key,
                }
            else:
                result.update(
                    validated=False,
                    validation_status="rejected",
                    validation_reason=signal or "Proof condition did not reproduce",
                )
        except (httpx.HTTPError, ScopeViolationError, ValueError, BudgetExceeded) as exc:
            result.update(
                validated=False, validation_status="inconclusive", validation_reason=str(exc)
            )
        return result

    async def validate_batch(self, findings: list[dict]) -> list[dict]:
        """Return all outcomes so reports can distinguish clean from untested."""
        return [await self.validate_finding(f) for f in findings]

    async def correlate_chains(self, findings: list[dict]) -> list[dict]:
        return correlate_chains([f for f in findings if f.get("validated")])

    async def aclose(self) -> None:
        await self._client.aclose()
