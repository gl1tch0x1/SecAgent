"""Operator-contracted, read-only proof of a private resource identity boundary."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

import httpx

from secagents.infra.execution_budget import ExecutionBudget
from secagents.infra.scope import enforce_scope


@dataclass(frozen=True)
class IdentityContract:
    owner_url: str
    other_control_url: str
    private_marker: str
    owner_header_env: str
    other_header_env: str


def load_identity_contracts(path: Path) -> list[IdentityContract]:
    """Read explicit GET-only cases; credentials remain in environment variables."""
    if path.stat().st_size > 64_000:
        raise ValueError("Identity proof contract exceeds 64 KB")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, list) or len(document) > 20:
        raise ValueError("Identity proof contract must contain at most 20 cases")
    contracts = []
    for item in document:
        if not isinstance(item, dict):
            raise ValueError("Identity proof case must be an object")
        contract = IdentityContract(**item)
        enforce_scope(contract.owner_url)
        enforce_scope(contract.other_control_url)
        if contract.owner_url == contract.other_control_url:
            raise ValueError("Owner and other control URLs must differ")
        if len(contract.private_marker) < 8:
            raise ValueError("Private marker must be at least eight characters")
        contracts.append(contract)
    return contracts


def _header_from_env(name: str) -> dict[str, str]:
    raw = os.environ.get(name)
    if not raw:
        raise ValueError(f"Identity header environment variable {name} is unset")
    key, separator, value = raw.partition(":")
    if not separator or not key.strip() or not value.strip() or "\r" in raw or "\n" in raw:
        raise ValueError(f"Identity header environment variable {name} is malformed")
    if key.lower() in {"host", "content-length", "transfer-encoding", "connection"}:
        raise ValueError("Identity proof header name is restricted")
    return {key.strip(): value.strip()}


async def prove_identity(
    contract: IdentityContract,
    budget: ExecutionBudget,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict:
    """Require two independent cross-identity leaks and clean controls."""
    enforce_scope(contract.owner_url)
    enforce_scope(contract.other_control_url)
    owner_headers = _header_from_env(contract.owner_header_env)
    other_headers = _header_from_env(contract.other_header_env)
    if owner_headers == other_headers:
        raise ValueError("Identity proof requires two distinct credentials")
    marker = contract.private_marker
    observations = []
    own_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=20, follow_redirects=False)
    try:
        for _ in range(2):
            for role, url, headers in (
                ("owner_resource", contract.owner_url, owner_headers),
                ("other_identity_owner_resource", contract.owner_url, other_headers),
                ("other_identity_control", contract.other_control_url, other_headers),
                ("anonymous_owner_resource", contract.owner_url, {}),
            ):
                async with budget.request(url):
                    response = await client.get(url, headers=headers)
                observations.append(
                    {
                        "role": role,
                        "status_code": response.status_code,
                        "body_sha256": hashlib.sha256(response.content).hexdigest(),
                        "private_marker_present": marker in response.text,
                    }
                )
    finally:
        if own_client:
            await client.aclose()
    owner, cross, other_control, anonymous = (
        observations[0::4],
        observations[1::4],
        observations[2::4],
        observations[3::4],
    )
    valid = (
        all(item["status_code"] == 200 and item["private_marker_present"] for item in owner)
        and all(item["status_code"] == 200 and item["private_marker_present"] for item in cross)
        and all(
            item["status_code"] == 200 and not item["private_marker_present"]
            for item in other_control
        )
        and all(not item["private_marker_present"] for item in anonymous)
    )
    return {
        "title": "Cross-identity private resource exposure",
        "check_key": "idor",
        "url": contract.owner_url,
        "severity": "high",
        "validated": valid,
        "validation_status": "validated" if valid else "rejected",
        "validation_reason": (
            "Private marker available to a second identity in two runs"
            if valid
            else "Identity controls did not prove a private resource leak"
        ),
        "proof": {
            "policy": "idor",
            "policy_version": "2.0",
            "evidence_class": "identity_boundary",
            "observations": observations,
        },
    }
