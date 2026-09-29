"""Typed contracts for scan phases, evidence, and validation outcomes.

These dataclasses reduce ambiguity in the orchestration layer and make the
scan pipeline easier to reason about, test, and audit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProofArtifact:
    """A single proof artifact that must exist for a phase result to be trusted."""

    kind: str
    source: str
    url: str
    method: str = "GET"
    status_code: int | None = None
    payload: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanContext:
    """Execution context shared across the scan lifecycle."""

    target: str
    domain: str
    depth: str
    workers: int
    results_dir: str
    max_requests: int
    requests_per_second_per_host: float
    max_duration_seconds: float
    auth_headers: dict[str, str] = field(default_factory=dict)
    api_spec_path: str | None = None
    har_paths: list[str] = field(default_factory=list)
    identity_contract_path: str | None = None
    state_contract_path: str | None = None
    ssrf_contract_path: str | None = None
    fuzz_payloads: bool = False
    max_payload_variants: int = 6
    fuzz_cooldown_seconds: float = 86400.0


@dataclass(frozen=True)
class EvidenceRecord:
    """A single evidence artifact collected during a phase."""

    phase: str
    kind: str
    url: str
    method: str = "GET"
    status_code: int | None = None
    payload: str | None = None
    proof_status: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)
    proof: ProofArtifact | None = None


@dataclass(frozen=True)
class ValidationOutcome:
    """Typed validation outcome for a candidate finding."""

    check_key: str
    title: str
    url: str
    validated: bool = False
    validation_status: str = "manual_lead"
    severity: str = "medium"
    confidence: float = 0.0
    payload_spec: dict[str, Any] | None = None
    proof: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PhaseContract:
    """Required structure for a phase result to be considered valid."""

    name: str
    required_payload_keys: tuple[str, ...] = ()
    required_evidence_kinds: tuple[str, ...] = ()
    required_proof_kinds: tuple[str, ...] = ()
    allow_empty_evidence: bool = False


@dataclass(frozen=True)
class PhaseResult:
    """Structured result returned by a scan phase."""

    name: str
    payload: dict[str, Any]
    evidence: list[EvidenceRecord] = field(default_factory=list)


def validate_phase_contract(phase_result: PhaseResult, contract: PhaseContract) -> None:
    """Fail fast when a phase is missing required result data or proof."""

    if contract.name != phase_result.name:
        raise ValueError(
            f"Phase contract mismatch: expected '{contract.name}', got '{phase_result.name}'"
        )

    missing_payload = [
        key for key in contract.required_payload_keys if key not in phase_result.payload
    ]
    if missing_payload:
        raise ValueError(f"Phase '{phase_result.name}' is missing payload keys: {missing_payload}")

    if contract.required_proof_kinds:
        if not any(e.proof is not None for e in phase_result.evidence):
            raise ValueError(f"Phase '{phase_result.name}' requires proof artifacts for validation")

    if not contract.allow_empty_evidence and not phase_result.evidence:
        raise ValueError(f"Phase '{phase_result.name}' requires at least one evidence record")

    evidence_kinds = {e.kind for e in phase_result.evidence}
    missing_evidence = tuple(
        kind for kind in contract.required_evidence_kinds if kind not in evidence_kinds
    )
    if missing_evidence:
        raise ValueError(
            f"Phase '{phase_result.name}' is missing required evidence kinds: {missing_evidence}"
        )

    proof_kinds = {e.proof.kind for e in phase_result.evidence if e.proof is not None}
    missing_proof = tuple(kind for kind in contract.required_proof_kinds if kind not in proof_kinds)
    if missing_proof:
        raise ValueError(
            f"Phase '{phase_result.name}' is missing proof artifacts for: {missing_proof}"
        )
