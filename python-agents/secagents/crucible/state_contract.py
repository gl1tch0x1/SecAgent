"""Opt-in state read, negative control, and cleanup for API write probes."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import httpx

from secagents.crucible.identity_proof import _header_from_env
from secagents.infra.execution_budget import BudgetExceeded, ExecutionBudget
from secagents.infra.scope import enforce_scope


WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class StateContract:
    read_url: str
    write_url: str
    write_method: str
    control_body: str
    probe_body: str
    cleanup_url: str
    cleanup_method: str
    cleanup_body: str
    baseline_marker: str
    probe_marker: str
    header_env: str


def load_state_contracts(path: Path) -> list[StateContract]:
    if path.stat().st_size > 64_000:
        raise ValueError("State contract exceeds 64 KB")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, list) or len(document) > 10:
        raise ValueError("State contract must contain at most 10 cases")
    contracts = []
    for item in document:
        if not isinstance(item, dict):
            raise ValueError("State contract case must be an object")
        contract = StateContract(**item)
        for url in (contract.read_url, contract.write_url, contract.cleanup_url):
            enforce_scope(url)
        if contract.write_method.upper() not in WRITE_METHODS:
            raise ValueError("State probe must use POST, PUT, PATCH or DELETE")
        if contract.cleanup_method.upper() not in WRITE_METHODS:
            raise ValueError("State cleanup must use POST, PUT, PATCH or DELETE")
        if (
            len(contract.baseline_marker) < 8
            or len(contract.probe_marker) < 8
            or contract.baseline_marker == contract.probe_marker
            or not contract.control_body
            or not contract.probe_body
        ):
            raise ValueError(
                "State contract requires distinct markers and nonempty control/probe bodies"
            )
        contracts.append(contract)
    return contracts


async def observe_state_contract(
    contract: StateContract,
    budget: ExecutionBudget,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict:
    """Run one controlled write and two independent probes, cleaning each in finally."""
    for url in (contract.read_url, contract.write_url, contract.cleanup_url):
        enforce_scope(url)
    if (
        budget.max_requests - budget.snapshot()["requests_used"] < 13
        or budget.remaining_seconds() < 90
    ):
        raise BudgetExceeded("State contract needs 13 reserved requests and 90 seconds for cleanup")
    headers = _header_from_env(contract.header_env)
    headers.setdefault("Content-Type", "application/json")
    own_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=5, follow_redirects=False)
    observations: list[dict] = []
    cleanup_failed = False

    async def read(role: str) -> httpx.Response:
        async with budget.request(contract.read_url):
            response = await client.get(contract.read_url, headers=headers)
        observations.append(
            {
                "role": role,
                "status_code": response.status_code,
                "body_sha256": hashlib.sha256(response.content).hexdigest(),
                "baseline_marker_present": contract.baseline_marker in response.text,
                "probe_marker_present": contract.probe_marker in response.text,
            }
        )
        return response

    async def write(url: str, method: str, body: str) -> httpx.Response:
        async with budget.request(url):
            return await client.request(method.upper(), url, headers=headers, content=body)

    try:
        await read("baseline")
        for role, body in (
            ("negative_control", contract.control_body),
            ("probe_1", contract.probe_body),
            ("probe_2", contract.probe_body),
        ):
            try:
                response = await write(contract.write_url, contract.write_method, body)
                observations.append({"role": role + "_write", "status_code": response.status_code})
                if response.status_code >= 400:
                    break
                await read(role + "_state")
            finally:
                try:
                    cleanup = await write(
                        contract.cleanup_url, contract.cleanup_method, contract.cleanup_body
                    )
                    observations.append(
                        {"role": role + "_cleanup", "status_code": cleanup.status_code}
                    )
                    if cleanup.status_code >= 400:
                        cleanup_failed = True
                except Exception:
                    cleanup_failed = True
                if not cleanup_failed:
                    await read(role + "_restored")
            if cleanup_failed:
                break
    finally:
        if own_client:
            await client.aclose()

    by_role = {item["role"]: item for item in observations}
    baseline = by_role.get("baseline", {})
    control = by_role.get("negative_control_state", {})
    valid = (
        not cleanup_failed
        and baseline.get("status_code") == 200
        and baseline.get("baseline_marker_present")
        and not baseline.get("probe_marker_present")
        and control.get("status_code") == 200
        and control.get("baseline_marker_present")
        and not control.get("probe_marker_present")
        and all(
            by_role.get(f"probe_{index}_state", {}).get("probe_marker_present")
            and by_role.get(f"probe_{index}_restored", {}).get("baseline_marker_present")
            and not by_role.get(f"probe_{index}_restored", {}).get("probe_marker_present")
            for index in (1, 2)
        )
        and all(
            item.get("status_code", 500) < 400
            for item in observations
            if item["role"].endswith("_cleanup")
        )
    )
    return {
        "title": "Operator-contracted API state change",
        "url": contract.write_url,
        "validated": False,
        "validation_status": "manual_lead" if valid else "inconclusive",
        "validation_reason": (
            "Repeatable state change and cleanup observed; vulnerability semantics require operator review"
            if valid
            else "State control, independent probe, or cleanup did not complete"
        ),
        "proof": {
            "evidence_class": "state_mutation",
            "controlled_state_change": valid,
            "cleanup_failed": cleanup_failed,
            "observations": observations,
        },
    }
