"""Explicit publication requirements for every built-in security check."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProofPolicy:
    evidence_class: str
    minimum_positive_runs: int
    negative_control: bool
    capability: str = "http"


PASSIVE = ProofPolicy("configuration_or_content", 1, False)
DIFFERENTIAL = ProofPolicy("differential_http", 3, True)
PATH_EXPOSURE = ProofPolicy("artifact_retrieval", 3, True)
BROWSER = ProofPolicy("browser_execution", 1, True, "browser_proof")
IDENTITY = ProofPolicy("identity_boundary", 2, True, "two_identities")
STATE = ProofPolicy("state_mutation", 2, True, "state_and_cleanup")
CALLBACK = ProofPolicy("out_of_band_callback", 1, True, "oast")
MANUAL = ProofPolicy("manual_review", 1, False, "operator_review")


PROOF_POLICIES: dict[str, ProofPolicy] = {
    "sqli": DIFFERENTIAL,
    "ssti": DIFFERENTIAL,
    "shellshock": CALLBACK,
    "cmdi": DIFFERENTIAL,
    "log4shell": CALLBACK,
    "nosqli": STATE,
    "git_exposed": PATH_EXPOSURE,
    "env_exposed": PATH_EXPOSURE,
    "lfi": DIFFERENTIAL,
    "rfi": CALLBACK,
    "ssrf": CALLBACK,
    "xxe": STATE,
    "jwt_none": IDENTITY,
    "oauth_redirect": DIFFERENTIAL,
    "idor": IDENTITY,
    "sensitive_data": PASSIVE,
    "admin_panel": MANUAL,
    "backup_file": PATH_EXPOSURE,
    "xss": BROWSER,
    "csrf": STATE,
    "open_redirect": DIFFERENTIAL,
    "cors": BROWSER,
    "graphql_introspection": MANUAL,
    "cache_poisoning": STATE,
    "ai_prompt_injection": MANUAL,
    "missing_sri": PASSIVE,
    "directory_listing": PASSIVE,
    "clickjacking": PASSIVE,
    "missing_headers": PASSIVE,
    "server_disclosure": PASSIVE,
}
