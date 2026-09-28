"""Unit tests for SmartCache, ProcessManager, ToolRegistry, BrowserAgent, and 12 Specialized AI Agents."""

import pytest
from secagents.core.cache import SmartCache
from secagents.core.process_manager import ProcessManager
from secagents.arsenal.registry import ToolRegistry
from secagents.agents.browser_agent import BrowserAgent
from secagents.agents.specialized import (
    IntelligentDecisionEngine,
    BugBountyWorkflowManager,
    CTFWorkflowManager,
    CVEIntelligenceManager,
    AIExploitGenerator,
    VulnerabilityCorrelator,
    TechnologyDetector,
    RateLimitDetector,
    FailureRecoverySystem,
    PerformanceMonitor,
    ParameterOptimizer,
    GracefulDegradation,
)


def test_smart_cache_lru():
    cache = SmartCache(maxsize=2, default_ttl=60)
    cache.set("key1", "val1")
    cache.set("key2", "val2")

    assert cache.get("key1") == "val1"
    assert cache.get("key2") == "val2"

    cache.set("key3", "val3")  # Evicts key1 or key2
    assert cache.get("key3") == "val3"


@pytest.mark.asyncio
async def test_process_manager_execution():
    pm = ProcessManager()
    res = await pm.run_command(["python", "-c", "print('hello_secagent')"], timeout=5)
    assert res["success"] is True
    assert "hello_secagent" in res["stdout"]


@pytest.mark.asyncio
async def test_process_manager_rejects_shell_strings():
    pm = ProcessManager()
    res = await pm.run_command("python -c print(1)")
    assert res["success"] is False
    assert "disabled" in res["stderr"]
    assert pm.history == []


def test_tool_registry_catalog():
    assert len(ToolRegistry.TOOLS_CATALOG) >= 50
    nmap = ToolRegistry.get_tool("nmap")
    assert nmap is not None
    assert nmap["name"] == "Nmap"


@pytest.mark.asyncio
async def test_browser_agent(monkeypatch):
    monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
    agent = BrowserAgent()
    out = await agent.execute({"target_url": "https://example.com"})
    assert out.confidence > 0.8
    assert "forms_detected" in out.result


@pytest.mark.asyncio
async def test_12_specialized_agents():
    agents = [
        IntelligentDecisionEngine(),
        BugBountyWorkflowManager(),
        CTFWorkflowManager(),
        CVEIntelligenceManager(),
        AIExploitGenerator(),
        VulnerabilityCorrelator(),
        TechnologyDetector(),
        RateLimitDetector(),
        FailureRecoverySystem(),
        PerformanceMonitor(),
        ParameterOptimizer(),
        GracefulDegradation(),
    ]

    assert len(agents) == 12
    for agent in agents:
        out = await agent.execute({"target": "example.com", "findings": [{"type": "sqli"}, {"type": "xss"}]})
        if isinstance(agent, AIExploitGenerator):
            assert out.result["status"] == "manual_lead"
            assert "poc_code" not in out.result
        elif isinstance(agent, TechnologyDetector):
            assert out.confidence == 0.0
            assert out.result["observed"] is False
        elif isinstance(agent, (CVEIntelligenceManager, VulnerabilityCorrelator)):
            assert out.confidence <= 0.1
        else:
            assert out.confidence > 0.7
        assert out.agent == agent.name
