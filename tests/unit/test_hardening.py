import logging
import os

import pytest

from secagents.config import AppConfig, ScanConfig, load_runtime_config
from secagents.core.orchestrator import Intent, Orchestrator
from secagents.core.skill_manager import skill_manager
from secagents.infra.security_policy import SecurityPolicy


def test_runtime_config_rejects_invalid_scan_settings(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    with pytest.raises(ValueError, match="max_requests"):
        AppConfig(
            target="https://example.com",
            scan=ScanConfig(
                target="https://example.com",
                max_requests=0,
                requests_per_second_per_host=0.0,
                max_duration_seconds=0.0,
            ),
        )


def test_security_policy_blocks_unapproved_targets(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    policy = SecurityPolicy.from_env()

    with pytest.raises(ValueError, match="not allowed"):
        policy.validate_target("https://evil.com")

    assert policy.validate_target("https://example.com") == "example.com"


def test_intent_classification_handles_real_world_phrases():
    orchestrator = Orchestrator()

    assert orchestrator.classify_intent("perform recon and discover exposed subdomains") == Intent.RECON
    assert orchestrator.classify_intent("generate an executive summary of all findings") == Intent.REPORT
    assert orchestrator.classify_intent("audit the app for prompt injection and repo poisoning") == Intent.AI_SAFETY


@pytest.mark.asyncio
async def test_notify_invocation_logs_warning_on_failure(monkeypatch, caplog):
    class FailingClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *args, **kwargs):
            raise RuntimeError("notification service unavailable")

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: FailingClient())

    with caplog.at_level(logging.WARNING):
        await skill_manager.notify_invocation("test-agent", "scan")

    assert "Failed to notify workflow invocation" in caplog.text
