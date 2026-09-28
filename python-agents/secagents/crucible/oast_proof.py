"""Opt-in SSRF proof using an approved, scan-bound out-of-band service."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from secagents.infra.execution_budget import ExecutionBudget
from secagents.infra.scope import enforce_scope
from secagents.modules.oast_browser import OASTClient


@dataclass(frozen=True)
class SSRFContract:
    probe_url: str
    parameter: str
    provider_url: str
    provider_token_env: str


def load_ssrf_contracts(path: Path) -> list[SSRFContract]:
    if path.stat().st_size > 64_000:
        raise ValueError("SSRF contract exceeds 64 KB")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, list) or len(document) > 5:
        raise ValueError("SSRF contract must contain at most five cases")
    contracts = []
    for item in document:
        if not isinstance(item, dict):
            raise ValueError("SSRF contract case must be an object")
        contract = SSRFContract(**item)
        enforce_scope(contract.probe_url)
        if not contract.parameter or not contract.provider_token_env:
            raise ValueError("SSRF contract needs a parameter and provider token variable")
        contracts.append(contract)
    return contracts


def _inject_callback(url: str, parameter: str, callback: str) -> str:
    parts = urlsplit(url)
    pairs = [(name, value) for name, value in parse_qsl(parts.query) if name != parameter]
    pairs.append((parameter, callback))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))


async def prove_ssrf(
    contract: SSRFContract,
    budget: ExecutionBudget,
    *,
    auth_headers: dict[str, str] | None = None,
    provider_client: httpx.AsyncClient | None = None,
    target_client: httpx.AsyncClient | None = None,
) -> dict:
    """Require a clean control and two independently registered callbacks."""
    enforce_scope(contract.probe_url)
    token = os.environ.get(contract.provider_token_env, "")
    if not token:
        raise ValueError("OAST provider token environment variable is unset")
    own_target = target_client is None
    if target_client is None:
        target_client = httpx.AsyncClient(timeout=15, follow_redirects=False)
    observations: list[dict[str, int | str | None]] = []
    callback_hashes = set()
    try:
        for role in ("negative_control", "positive_probe", "positive_replay"):
            provider = OASTClient(
                contract.provider_url,
                token=token,
                budget=budget,
                client=provider_client,
            )
            callback = await provider.register()
            callback_hash = hashlib.sha256(callback.encode()).hexdigest()
            if callback_hash in callback_hashes:
                raise ValueError("OAST provider reused a callback URL")
            callback_hashes.add(callback_hash)
            target_status = None
            if role != "negative_control":
                probe_url = _inject_callback(contract.probe_url, contract.parameter, callback)
                enforce_scope(probe_url)
                async with budget.request(probe_url):
                    response = await target_client.get(probe_url, headers=auth_headers or {})
                target_status = response.status_code
            events = await provider.poll(timeout=0 if role == "negative_control" else 5)
            observations.append(
                {
                    "role": role,
                    "target_status_code": target_status,
                    "callback_sha256": callback_hash,
                    "matching_events": len(events),
                }
            )
    finally:
        if own_target:
            await target_client.aclose()
    valid = (
        len(observations) == 3
        and observations[0]["matching_events"] == 0
        and all(
            isinstance(item["matching_events"], int)
            and item["matching_events"] > 0
            and item["target_status_code"] is not None
            and isinstance(item["target_status_code"], int)
            and item["target_status_code"] < 500
            for item in observations[1:]
        )
    )
    return {
        "title": "Server-side request to operator callback",
        "url": contract.probe_url,
        "check_key": "ssrf",
        "severity": "high",
        "validated": valid,
        "validation_status": "validated" if valid else "rejected",
        "validation_reason": (
            "Two independent, scan-bound callbacks observed"
            if valid
            else "OAST control or independent callback replay failed"
        ),
        "proof": {
            "policy": "ssrf",
            "policy_version": "2.0",
            "evidence_class": "out_of_band_callback",
            "observations": observations,
        },
    }
