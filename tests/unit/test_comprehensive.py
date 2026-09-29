"""Comprehensive test suite for SecAgents core components."""

import pytest
import asyncio


# Test fixtures
@pytest.fixture
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ============================================================================
# ORCHESTRATOR TESTS
# ============================================================================


class TestOrchestrator:
    """Test suite for orchestration engine."""

    @pytest.mark.asyncio
    async def test_task_decomposition(self):
        """Test intent decomposition into task DAG."""
        from secagents.core.orchestrator import Intent, Task, ExecutionGraph, TaskState

        # Create execution graph
        graph = ExecutionGraph(root_intent=Intent.SCAN)

        # Add tasks
        recon_task = Task(intent=Intent.RECON, agent="recon", action="discover")
        scan_task = Task(
            intent=Intent.SCAN,
            agent="web_security",
            action="scan",
            depends_on=[recon_task.id],
        )

        graph.tasks = [recon_task, scan_task]

        # Test ready tasks
        ready = graph.ready_tasks
        assert len(ready) == 1
        assert ready[0].id == recon_task.id

        # Mark recon as done
        recon_task.state = TaskState.DONE

        # Now scan should be ready
        ready = graph.ready_tasks
        assert len(ready) == 1
        assert ready[0].id == scan_task.id

    @pytest.mark.asyncio
    async def test_task_dependency_resolution(self):
        """Test dependency resolution in execution graph."""
        from secagents.core.orchestrator import Task, ExecutionGraph, TaskState, Intent

        graph = ExecutionGraph()

        # Create task chain: A -> B -> C
        task_a = Task(id="a", intent=Intent.RECON)
        task_b = Task(id="b", intent=Intent.SCAN, depends_on=["a"])
        task_c = Task(id="c", intent=Intent.VALIDATE, depends_on=["b"])

        graph.tasks = [task_a, task_b, task_c]

        # Only A should be ready initially
        assert len(graph.ready_tasks) == 1
        assert graph.ready_tasks[0].id == "a"

        # Complete A
        task_a.state = TaskState.DONE
        assert len(graph.ready_tasks) == 1
        assert graph.ready_tasks[0].id == "b"

        # Complete B
        task_b.state = TaskState.DONE
        assert len(graph.ready_tasks) == 1
        assert graph.ready_tasks[0].id == "c"

    def test_circuit_breaker_pattern(self):
        """Test circuit breaker for failure isolation."""
        from secagents.core.orchestrator import CircuitBreakerState

        cb = CircuitBreakerState(failure_threshold=3, success_threshold=2)

        # Test open state
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()

        assert cb.is_open

        # Test half-open state
        cb.reset_for_testing()
        assert not cb.is_open


# ============================================================================
# AGENT TESTS
# ============================================================================


class TestPhaseContracts:
    """Regression tests for typed phase contracts and proof enforcement."""

    def test_phase_contract_requires_proof_for_external_intel(self):
        from secagents.infra.scan_contracts import (
            EvidenceRecord,
            PhaseContract,
            PhaseResult,
            ProofArtifact,
            validate_phase_contract,
        )

        valid = PhaseResult(
            name="external_intel",
            payload={"status": "completed"},
            evidence=[
                EvidenceRecord(
                    phase="external_intel",
                    kind="intel_provider",
                    url="https://example.com",
                    method="GET",
                    proof=ProofArtifact(
                        kind="intel_provider",
                        source="shodan",
                        url="https://example.com",
                        method="GET",
                        status_code=200,
                        metadata={"provider": "shodan"},
                    ),
                )
            ],
        )
        validate_phase_contract(
            valid,
            PhaseContract(
                name="external_intel",
                required_evidence_kinds=("intel_provider",),
                required_proof_kinds=("intel_provider",),
                required_payload_keys=("status",),
            ),
        )

        invalid = PhaseResult(
            name="external_intel", payload={"status": "completed"}, evidence=[]
        )
        with pytest.raises(ValueError, match="proof"):
            validate_phase_contract(
                invalid,
                PhaseContract(
                    name="external_intel",
                    required_evidence_kinds=("intel_provider",),
                    required_proof_kinds=("intel_provider",),
                    required_payload_keys=("status",),
                ),
            )


class TestSecurityPolicies:
    """Regression tests for fail-closed security enforcement."""

    def test_validate_operation_blocks_write_without_permission(self):
        from secagents.infra.security_policy import (
            SecurityPolicy,
            SecurityPolicyViolation,
        )

        policy = SecurityPolicy(allowed_domains=["example.com"])

        with pytest.raises(
            SecurityPolicyViolation, match="write operations are disabled"
        ):
            policy.validate_operation("create_session", is_write=True)

    def test_validate_operation_requires_proof_for_ssrf(self):
        from secagents.infra.security_policy import (
            SecurityPolicy,
            SecurityPolicyViolation,
        )

        policy = SecurityPolicy(
            allowed_domains=["example.com"],
            allow_ssrf=True,
            require_proof_for_ssrf=True,
        )

        with pytest.raises(SecurityPolicyViolation, match="proof artifact"):
            policy.validate_operation("callback_probe", is_ssrf=True)

    def test_validate_operation_requires_proof_for_state_change(self):
        from secagents.infra.security_policy import (
            SecurityPolicy,
            SecurityPolicyViolation,
        )

        policy = SecurityPolicy(
            allowed_domains=["example.com"], allow_write_operations=True
        )

        with pytest.raises(SecurityPolicyViolation, match="proof artifact"):
            policy.validate_operation(
                "update_account", is_write=True, requires_proof=True
            )

    def test_sensitive_policy_requires_bound_contract(self):
        from secagents.infra.security_policy import (
            OperationAuthorization,
            SecurityPolicy,
            SecurityPolicyViolation,
        )

        policy = SecurityPolicy(
            allowed_domains=["example.com"], allow_write_operations=True
        )
        with pytest.raises(SecurityPolicyViolation, match="proof artifact"):
            policy.validate_operation(
                "state_write",
                is_write=True,
                target="https://example.com/item",
                proof_artifact={"ok": True},
            )
        with pytest.raises(SecurityPolicyViolation, match="proof artifact"):
            policy.validate_operation(
                "state_write",
                is_write=True,
                target="https://example.com/item",
                proof_artifact=OperationAuthorization(
                    "state_contract", "state_write", "https://example.com/other"
                ),
            )
        policy.validate_operation(
            "state_write",
            is_write=True,
            target="https://example.com/item",
            proof_artifact=OperationAuthorization(
                "state_contract", "state_write", "https://example.com/item"
            ),
        )

    def test_config_requires_allowed_domains(self):
        from secagents.config import build_scan_config

        with pytest.raises(ValueError, match="ALLOWED_DOMAINS"):
            build_scan_config(
                env={"ALLOWED_DOMAINS": "", "SECAGENT_TARGET": "example.com"}
            )


class TestAgents:
    """Test suite for all agent types."""

    @pytest.mark.asyncio
    async def test_supervisor_intent_classification(self):
        """Test supervisor's intent classification."""
        from secagents.agents.supervisor import SupervisorAgent

        agent = SupervisorAgent()

        task = {
            "action": "classify_intent",
            "objective": "recon the target",
            "scope": {"target": "example.com"},
        }

        output = await agent.execute(task)

        assert output.confidence > 0.7
        assert "classified_intent" in output.result
        assert output.result["classified_intent"] == "reconnaissance"

    @pytest.mark.asyncio
    async def test_planner_phase_decomposition(self):
        """Test planner's phase decomposition."""
        from secagents.agents.planner import PlannerAgent

        agent = PlannerAgent()

        task = {
            "objective": "scan for vulnerabilities",
            "scope": {"target": "example.com"},
            "constraints": {},
        }

        output = await agent.execute(task)

        assert output.confidence > 0.7
        assert "phases" in output.result
        assert len(output.result["phases"]) > 0

    @pytest.mark.asyncio
    async def test_recon_agent_discovery(self, monkeypatch):
        """Test recon agent's discovery capabilities with hermetic mocking."""
        from secagents.agents.recon import ReconAgent
        import httpx

        class MockResponse:
            status_code = 200
            text = '<html><a href="http://sub.example.com/login">Link</a></html>'

        class MockAsyncClient:
            async def get(self, *args, **kwargs):
                return MockResponse()

            async def aclose(self):
                pass

        monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: MockAsyncClient())

        monkeypatch.setenv("ALLOWED_DOMAINS", "example.com")
        agent = ReconAgent()
        task = {"action": "subdomain_enum", "target": "example.com"}

        output = await agent.execute(task)

        assert output.confidence >= 0.7
        assert (
            "subdomains" in output.result
            or "findings" in output.result
            or "error" in output.result
        )

    @pytest.mark.asyncio
    async def test_validator_finding_validation(self):
        """Test validator's finding validation."""
        from secagents.agents.validator import ValidatorAgent

        agent = ValidatorAgent()

        task = {
            "findings": [
                {
                    "type": "xss",
                    "endpoint": "/search",
                    "parameter": "q",
                    "poc": "q=<img+src=x+onerror=alert(1)>",
                }
            ]
        }

        output = await agent.execute(task)

        assert output.confidence >= 0.0
        assert "validated" in output.result or "error" in output.result
        assert output.result["validated"] == []
        assert output.result["inconclusive"][0]["validation_status"] == "manual_lead"

        spoofed = await agent.execute(
            {
                "findings": [
                    {
                        "validated": True,
                        "validation_status": "validated",
                        "proof": {
                            "policy": "sqli",
                            "observations": [{"status_code": 200}],
                        },
                    }
                ]
            }
        )
        assert spoofed.result["validated"] == []


# ============================================================================
# WORKER POOL TESTS
# ============================================================================


class TestWorkerPool:
    """Test suite for worker pool and task queue."""

    @pytest.mark.asyncio
    async def test_task_queue_fifo(self):
        """Test task queue FIFO behavior."""
        from secagents.core.workers import TaskQueue, Task

        queue = TaskQueue(max_size=10)

        # Add tasks
        t1 = Task(id="t1")
        t2 = Task(id="t2")
        t3 = Task(id="t3")

        queue.add(t1)
        queue.add(t2)
        queue.add(t3)

        # Remove in order
        assert queue.get().id == "t1"
        assert queue.get().id == "t2"
        assert queue.get().id == "t3"

    @pytest.mark.asyncio
    async def test_worker_pool_execution(self):
        """Test worker pool task execution."""
        from secagents.core.workers import WorkerPool, TaskQueue, Task

        pool = WorkerPool(num_workers=2)
        queue = TaskQueue()

        # Create mock task
        task = Task(id="test", input={"action": "test"})
        queue.add(task)

        # Start pool
        await pool.start(queue)

        # Check running
        assert pool.is_running

        # Stop pool
        await pool.stop()


# ============================================================================
# MEMORY SYSTEM TESTS
# ============================================================================


class TestMemorySystem:
    """Test suite for memory persistence."""

    def test_persistent_memory_storage(self):
        """Test persistent memory storage."""
        from secagents.core.memory import PersistentMemory

        memory = PersistentMemory()

        # Store finding
        memory.store(
            "finding_1", {"type": "xss", "severity": "high", "target": "example.com"}
        )

        # Retrieve
        finding = memory.retrieve("finding_1")
        assert finding["type"] == "xss"

    def test_memory_graph_relationships(self):
        """Test memory graph relationships."""
        from secagents.engine.memory_graph import MemoryGraph

        graph = MemoryGraph()

        # Add entities and relationships
        graph.add_entity("finding_1", "xss")
        graph.add_entity("endpoint_1", "endpoint")
        graph.add_relationship("finding_1", "affects", "endpoint_1")

        # Query relationships
        related = graph.get_related("finding_1")
        assert len(related) > 0


# ============================================================================
# CVE CHECKS TESTS
# ============================================================================


class TestCVEChecks:
    """Test suite for CVE check payloads."""

    def test_sqli_payload_generation(self):
        """Test SQL injection payload generation."""
        from secagents.modules.cve_checks import generate_sqli_payloads

        payloads = generate_sqli_payloads()
        assert len(payloads) > 0
        assert any("'" in p for p in payloads)

    def test_xss_payload_generation(self):
        """Test XSS payload generation."""
        from secagents.modules.cve_checks import generate_xss_payloads

        payloads = generate_xss_payloads()
        assert len(payloads) > 0
        assert any("<" in p for p in payloads)

    def test_ssti_payload_generation(self):
        """Test SSTI payload generation."""
        from secagents.modules.cve_checks import generate_ssti_payloads

        payloads = generate_ssti_payloads()
        assert len(payloads) > 0
        assert any("{" in p for p in payloads)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


class TestIntegration:
    """Integration tests for full workflows."""

    @pytest.mark.asyncio
    async def test_full_scan_workflow(self):
        """Test complete scan workflow from start to finish."""
        from secagents.core.orchestrator import Orchestrator, Intent

        orchestrator = Orchestrator()

        # Start scan workflow
        result = await orchestrator.execute_workflow(
            intent=Intent.SCAN, target="example.com", scope=".example.com"
        )

        assert result is not None
        assert "findings" in result or "status" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
