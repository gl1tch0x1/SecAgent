"""Unit test suite for AuraMemoryManager."""

import tempfile
import hashlib
from pathlib import Path
import pytest

from secagents.core.aura_memory import AuraMemoryManager, TargetDNA


@pytest.fixture
def temp_memory():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = Path(tmpdir) / "test_cognitive_memory.db"
        AuraMemoryManager._instance = None
        manager = AuraMemoryManager(db_path=db_path)
        yield manager
        AuraMemoryManager._instance = None


def test_remember_and_recall_target_dna(temp_memory: AuraMemoryManager):
    dna = TargetDNA(
        target="example.com",
        domain="example.com",
        tech_stack=["Nginx", "React"],
        waf_signature="Cloudflare",
        rate_limit_detected=True,
        recommended_concurrency=4,
    )

    temp_memory.remember_target_dna(dna)
    recalled = temp_memory.recall_target_dna("example.com")

    assert recalled is not None
    assert recalled.target == "example.com"
    assert recalled.waf_signature == "Cloudflare"
    assert recalled.rate_limit_detected is True
    assert "React" in recalled.tech_stack


def test_crystallize_and_recall_pattern(temp_memory: AuraMemoryManager):
    pid = temp_memory.crystallize_pattern(
        target="example.com",
        vuln_type="sqli",
        payload="' OR 1=1--",
        waf_bypassed=True,
        confidence=0.9,
    )

    assert pid.startswith("sqli:")
    assert pid == "sqli:" + hashlib.sha256(
        b"example.com\0sqli\0' OR 1=1--"
    ).hexdigest()
    patterns = temp_memory.recall_patterns_for_target("example.com")

    assert len(patterns) == 1
    assert patterns[0].vuln_type == "sqli"
    assert patterns[0].waf_bypassed is True


def test_pattern_reinforcement(temp_memory: AuraMemoryManager):
    temp_memory.crystallize_pattern(
        "example.com", "xss", "<script>alert(1)</script>", confidence=0.8
    )
    temp_memory.crystallize_pattern(
        "example.com", "xss", "<script>alert(1)</script>", confidence=0.8
    )

    patterns = temp_memory.recall_patterns_for_target("example.com", vuln_type="xss")
    assert len(patterns) == 1
    assert patterns[0].occurrences == 2
    assert patterns[0].confidence > 0.8

    reopened = AuraMemoryManager(db_path=temp_memory.db_path)
    reopened.crystallize_pattern("example.com", "xss", "<script>alert(1)</script>")
    assert (
        reopened.recall_patterns_for_target("example.com", vuln_type="xss")[
            0
        ].occurrences
        == 3
    )


def test_memory_inspection(temp_memory: AuraMemoryManager):
    temp_memory.remember_target_dna(TargetDNA("test.com", "test.com"))
    temp_memory.crystallize_pattern("test.com", "idor", "/api/user/1")

    info = temp_memory.inspect_memory()
    assert info["target_dna_count"] >= 1
    assert info["cognitive_patterns_count"] >= 1


def test_fuzz_attempts_are_hashed_and_not_repeated_until_cooldown(
    temp_memory: AuraMemoryManager,
):
    assert temp_memory.claim_fuzz_attempt("target-hash", "sqli", "payload-hash")
    temp_memory.record_fuzz_outcome("target-hash", "sqli", "payload-hash", "no_signal")
    temp_memory.record_fuzz_feedback("target-hash", "sqli", "percent_encode", False)
    temp_memory.record_fuzz_feedback("target-hash", "sqli", "percent_encode", True)
    assert temp_memory.recall_fuzz_feedback("target-hash", "sqli") == {
        "percent_encode": (2, 1)
    }
    assert temp_memory.inspect_memory()["fuzz_attempt_count"] == 1
    assert not temp_memory.claim_fuzz_attempt("target-hash", "sqli", "payload-hash")
    assert temp_memory.claim_fuzz_attempt(
        "target-hash", "sqli", "payload-hash", retry_after_seconds=0
    )
    temp_memory.release_fuzz_attempt("target-hash", "sqli", "payload-hash")
    assert temp_memory.claim_fuzz_attempt("target-hash", "sqli", "payload-hash")
