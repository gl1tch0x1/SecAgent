"""Structured replay metadata for findings with validated proof."""

from __future__ import annotations

import hashlib

from secagents.infra.scope import ScopeViolationError, enforce_scope


class PoCGenerator:
    """Expose the validated request without inventing an exploit verdict."""

    def generate(self, finding: dict) -> dict:
        poc = finding.get("poc") or {}
        if not finding.get("validated") or not isinstance(poc, dict):
            return {"status": "manual_lead", "fingerprint": self._fingerprint(finding)}
        method = str(poc.get("method", "")).upper()
        if method != "GET" or not poc.get("proof_policy") or not poc.get("url"):
            return {"status": "manual_lead", "fingerprint": self._fingerprint(finding)}
        try:
            enforce_scope(poc["url"])
        except ScopeViolationError:
            return {"status": "manual_lead", "fingerprint": self._fingerprint(finding)}
        return {
            "status": "replay_available",
            "request": {
                "method": method,
                "url": poc["url"],
                "proof_policy": poc["proof_policy"],
            },
            "fingerprint": self._fingerprint(finding),
        }

    @staticmethod
    def _fingerprint(finding: dict) -> str:
        raw = (
            f"{finding.get('title', '')}|{finding.get('location', '')}|{finding.get('payload', '')}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()


class ConsensusLLM:
    """Multi-model consensus for finding verification."""

    def __init__(self, models: list[str] | None = None, min_agreement: int = 2):
        self.models = models or ["openai", "anthropic", "groq"]
        self.min_agreement = min_agreement
        self.confidence_threshold = 0.75

    async def verify(self, finding: dict, llm_fn) -> dict:
        """Send finding to multiple models, synthesize consensus."""
        votes: list[dict] = []
        for model in self.models:
            try:
                result = await llm_fn(finding, model=model)
                votes.append(
                    {
                        "model": model,
                        "valid": result.get("valid", False),
                        "confidence": result.get("confidence", 0.5),
                    }
                )
            except Exception:
                continue

        valid_votes = sum(
            1 for v in votes if v["valid"] and v["confidence"] >= self.confidence_threshold
        )
        avg_confidence = sum(v["confidence"] for v in votes) / max(len(votes), 1)

        return {
            "consensus": valid_votes >= self.min_agreement,
            "votes": votes,
            "agreement": valid_votes,
            "avg_confidence": round(avg_confidence, 3),
        }
