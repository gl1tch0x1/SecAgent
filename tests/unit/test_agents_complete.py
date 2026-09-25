"""Complete test suite for all SecAgents agents — Updated for 0.3.0-dev."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

# ============================================================================
# SUPERVISOR AGENT TESTS
# ============================================================================

class TestSupervisorAgent:
    """Test suite for supervisor agent."""
    
    @pytest.mark.asyncio
    async def test_intent_classification_reconnaissance(self):
        """Test supervisor classifies reconnaissance intent."""
        from secagents.agents.supervisor import SupervisorAgent
        
        agent = SupervisorAgent()
        
        task = {
            "action": "classify_intent",
            "objective": "discover subdomains and endpoints for example.com",
            "scope": {"target": "example.com"}
        }
        
        output = await agent.execute(task)
        
        assert output.confidence >= 0.7
        assert "classified_intent" in output.result
        assert output.result["classified_intent"] == "reconnaissance"

    @pytest.mark.asyncio
    async def test_intent_classification_web3(self):
        """Test supervisor classifies web3 auditing intent."""
        from secagents.agents.supervisor import SupervisorAgent
        
        agent = SupervisorAgent()
        
        task = {
            "action": "classify_intent",
            "objective": "audit smart contract for rug pull vectors",
            "scope": {"target": "0x123..."}
        }
        
        output = await agent.execute(task)
        
        assert output.confidence >= 0.7
        assert output.result["classified_intent"] == "web3_auditing"

# ============================================================================
# PLANNER AGENT TESTS
# ============================================================================

class TestPlannerAgent:
    """Test suite for planner agent."""
    
    @pytest.mark.asyncio
    async def test_full_scan_planning(self):
        """Test planner creates full scan plan."""
        from secagents.agents.planner import PlannerAgent
        
        agent = PlannerAgent()
        
        task = {
            "objective": "perform full security assessment",
            "scope": {"target": "example.com"},
            "constraints": {"time_limit": 3600}
        }
        
        output = await agent.execute(task)
        
        assert output.confidence >= 0.7
        assert "phases" in output.result
        assert len(output.result["phases"]) > 0
        
        # Check phase structure
        first_phase = output.result["phases"][0]
        assert "phase" in first_phase
        assert "tasks" in first_phase

# ============================================================================
# WEB SECURITY AGENT TESTS
# ============================================================================

class TestWebSecurityAgent:
    """Test suite for web security agent."""
    
    @pytest.mark.asyncio
    async def test_scan_execution(self, monkeypatch):
        """Test web security scan execution."""
        from secagents.agents.web_security import WebSecurityAgent

        monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
        
        agent = WebSecurityAgent()
        
        # Mock httpx client response
        mock_resp = MagicMock()
        mock_resp.text = "Normal response"
        mock_resp.status_code = 200
        
        # Patch the private _client or the httpx AsyncClient directly
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            
            task = {
                "target": "http://example.com",
                "endpoints": ["/search"],
                "vuln_types": ["xss", "sqli"]
            }
            
            output = await agent.execute(task)
            
            assert output.confidence >= 0.6
            assert "findings" in output.result
            assert output.result["endpoints_tested"] == 1
            assert mock_get.call_count > 0
            assert mock_get.call_args.args[0] == "http://example.com/search"

    @pytest.mark.asyncio
    async def test_signature_requires_clean_baseline_and_stays_manual(self, monkeypatch):
        from secagents.agents.web_security import WebSecurityAgent

        monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")

        agent = WebSecurityAgent()

        async def reflected_for_every_request(endpoint, payload, target):
            return "SQL syntax error"

        monkeypatch.setattr(agent, "_send_payload", reflected_for_every_request)
        assert await agent._test("/search", "sqli", "https://example.com") is None

        async def distinct_probe(endpoint, payload, target):
            return "normal" if payload == "safe_canary_value" else "SQL syntax error"

        monkeypatch.setattr(agent, "_send_payload", distinct_probe)
        lead = await agent._test("/search", "sqli", "https://example.com")
        assert lead is not None
        assert lead["validation_status"] == "manual_lead"
        assert lead["validated"] is False

    @pytest.mark.asyncio
    async def test_absolute_inventory_url_uses_shared_budget(self, monkeypatch):
        from secagents.agents.web_security import WebSecurityAgent
        from secagents.infra.execution_budget import ExecutionBudget

        monkeypatch.setenv("ALLOWED_DOMAINS", "example.com,api.example.com")
        budget = ExecutionBudget(
            max_requests=2,
            requests_per_second_per_host=1000,
            max_duration_seconds=10,
        )
        agent = WebSecurityAgent(budget=budget, auth_headers={"X-Scan-Session": "fixture"})
        response = MagicMock(text="normal", status_code=200)
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response) as get:
            output = await agent.execute({
                "target": "https://example.com/app",
                "endpoints": ["https://api.example.com/search"],
                "vuln_types": ["sqli"],
            })

        assert get.call_count == 2
        assert all(call.args[0] == "https://api.example.com/search" for call in get.call_args_list)
        assert output.result["budget"]["requests_used"] == 2
        assert output.result["budget"]["termination_reason"] == "request_limit_exceeded"
        assert agent.budget is budget

    @pytest.mark.asyncio
    async def test_out_of_scope_inventory_url_sends_no_request(self, monkeypatch):
        from secagents.agents.web_security import WebSecurityAgent

        monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
        agent = WebSecurityAgent()
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as get:
            output = await agent.execute({
                "target": "https://example.com",
                "endpoints": ["https://other.example.net/search"],
                "vuln_types": ["sqli"],
            })
        get.assert_not_called()
        assert output.result["budget"]["requests_used"] == 0

    def test_relative_endpoint_uses_target_directory_without_query(self):
        from secagents.agents.web_security import WebSecurityAgent

        assert WebSecurityAgent._resolve_endpoint(
            "https://example.com/app?session=private", "search"
        ) == "https://example.com/app/search"

    @pytest.mark.asyncio
    async def test_specialist_ssrf_requires_callback_contract(self, monkeypatch):
        from secagents.agents.web_security import WebSecurityAgent
        from secagents.armada.handlers import build_scan_handlers

        handlers = build_scan_handlers({"target": "example.com"})
        result = await handlers["ssrf"](context={}, action="ssrf")
        assert result["findings"] == []
        assert "callback" in result["coverage_gap"]
        assert "ssrf" not in WebSecurityAgent.VULN_SIGNATURES

        monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as get:
            output = await WebSecurityAgent().execute({
                "target": "https://example.com",
                "endpoints": ["/fetch"],
                "vuln_types": ["ssrf"],
            })
        get.assert_not_called()
        assert output.result["vuln_types_tested"] == 0
        assert output.result["coverage_gaps"][0]["vuln_type"] == "ssrf"

# ============================================================================
# API SECURITY AGENT TESTS
# ============================================================================

class TestAPISecurityAgent:
    """Test suite for API security agent."""
    
    @pytest.mark.asyncio
    async def test_api_scan_execution(self):
        """Test API security scan execution."""
        from secagents.agents.api_security import APISecurityAgent
        
        agent = APISecurityAgent()
        
        # Mock httpx client
        mock_resp = MagicMock()
        mock_resp.text = "{}"
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_resp.headers = {}
        
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_resp
            
            task = {
                "target": "https://api.example.com",
                "endpoints": [{"path": "/users/1", "method": "GET"}]
            }
            
            output = await agent.execute(task)
            
            assert output.confidence >= 0.6
            assert "findings" in output.result
            assert output.result["endpoints_tested"] == 1

# ============================================================================
# WEB3 SECURITY AGENT TESTS
# ============================================================================

class TestWeb3SecurityAgent:
    """Test suite for Web3 security agent."""
    
    @pytest.mark.asyncio
    async def test_contract_audit(self):
        """Test smart contract auditing."""
        from secagents.agents.web3_security import Web3SecurityAgent
        from pathlib import Path
        
        agent = Web3SecurityAgent()
        
        # We patch rglob at the instance level or the Path class
        # Correctly mock Path.rglob to return our mock file
        mock_file = MagicMock(spec=Path)
        mock_file.is_file.return_value = True
        mock_file.read_text.return_value = "function mint() public {}"
        mock_file.parts = ["contract.sol"]
        mock_file.suffix = ".sol"
        mock_file.__str__.return_value = "contract.sol"
        
        with patch("pathlib.Path.rglob", return_value=[mock_file]), \
             patch("pathlib.Path.is_dir", return_value=True), \
             patch("pathlib.Path.is_file", return_value=False):
            
            task = {
                "target_path": "contracts/",
                "chain": "evm"
            }
            
            output = await agent.execute(task)
            
            assert output.confidence >= 0.7
            assert "findings" in output.result
            assert len(output.result["findings"]) > 0
            assert any(f["title"] == "Public mint function" for f in output.result["findings"])

# ============================================================================
# REPORT AGENT TESTS
# ============================================================================

class TestReportAgent:
    """Test suite for report agent."""
    
    @pytest.mark.asyncio
    async def test_impact_first_report_generation(self):
        """Test impact-first report generation."""
        from secagents.agents.report import ReportAgent
        
        agent = ReportAgent()
        
        task = {
            "findings": [
                {
                    "type": "rce",
                    "severity": "critical",
                    "title": "Remote Code Execution",
                    "description": "Critical RCE found"
                }
            ],
            "target": "example.com",
            "format": "markdown"
        }
        
        output = await agent.execute(task)
        
        assert output.confidence == 1.0
        assert "report" in output.result
        assert "## 1. Executive Summary" in output.result["report"]
        assert "[CRITICAL]" in output.result["report"]

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
