"""Module 6: Planner, specialist hiring, and horizontal scaling."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
from typing import Any, Callable, Awaitable
from secagents.core.orchestrator import Orchestrator, Intent, ExecutionGraph

logger = logging.getLogger(__name__)


@dataclass
class AgentSpec:
    name: str
    role: str
    handler: Callable[..., Awaitable[Any]] | None = None


# Specialist agents mapped to scan phases
DEFAULT_SPECIALISTS = [
    AgentSpec("port_scan", "Port Scan Agent"),
    AgentSpec("subdomain", "Subdomain Enumeration Agent"),
    AgentSpec("web_crawl", "Web Crawl Agent"),
    AgentSpec("sqli", "SQLi Agent"),
    AgentSpec("xss", "XSS Agent"),
    AgentSpec("ssrf", "SSRF Agent"),
    AgentSpec("idor", "IDOR Agent"),
    AgentSpec("universal_scan", "Universal Scan Agent"),
]


class ArmadaOrchestrator:
    """
    Decomposes missions into DAGs and dispatches specialist agents.
    Supports --workers N for parallel execution.
    """

    def __init__(self, workers: int = 4):
        self.workers = max(1, workers)
        self._orchestrator = Orchestrator()
        self._specialists: dict[str, AgentSpec] = {s.name: s for s in DEFAULT_SPECIALISTS}
        self._handlers: dict[str, Callable] = {}

    def register_handler(self, agent_name: str, handler: Callable[..., Awaitable[Any]]) -> None:
        self._handlers[agent_name] = handler
        if agent_name in self._specialists:
            self._specialists[agent_name].handler = handler

    def plan_mission(self, target: str, depth: str = "standard") -> ExecutionGraph:
        """Planner Agent: build DAG from high-level goal."""
        from secagents.core.aura_memory import AuraMemoryManager

        # Consult Cognitive Memory prior to DAG building
        memory = AuraMemoryManager.get_instance()
        dna = memory.recall_target_dna(target)

        adjusted_depth = depth
        if dna:
            logger.info(
                f"ArmadaSwarm: Recalled Target DNA for {target}. "
                f"Rate Limited: {dna.rate_limit_detected}, WAF: {dna.waf_signature or 'None'}"
            )

        intent = Intent.SCAN
        context = {"target": target, "depth": adjusted_depth, "recalled_dna": dna}
        graph = self._orchestrator.decompose_intent(intent, context)

        # Route tasks to appropriate specialist agents based on action semantics
        action_routing = {
            "full_recon": "subdomain",
            "universal_scan": "universal_scan",
        }
        for task in graph.tasks:
            routed = action_routing.get(task.action)
            if routed and routed in self._specialists:
                task.agent = routed
            elif task.agent not in self._specialists:
                # An unknown action must fail visibly, never run a different tool.
                logger.warning("No specialist registered for action %s", task.action)
        return graph

    def hire_specialists(self, graph: ExecutionGraph) -> list[AgentSpec]:
        """Return specialist agents needed for this DAG."""
        needed = {t.agent for t in graph.tasks if t.agent}
        return [self._specialists[n] for n in needed if n in self._specialists]

    async def execute(self, graph: ExecutionGraph, context: dict) -> dict:
        """Execute DAG with worker pool parallelism."""
        from secagents.core.orchestrator import TaskState

        results: dict[str, Any] = {"tasks": {}, "findings": [], "failures": []}
        sem = asyncio.Semaphore(self.workers)

        async def run_task(task_obj: Any) -> None:
            async with sem:
                task_obj.state = TaskState.RUNNING
                handler = self._handlers.get(task_obj.agent)
                try:
                    if handler:
                        out = await handler(context=context, action=task_obj.action)
                        task_obj.state = TaskState.DONE
                    else:
                        out = {
                            "status": "skipped",
                            "agent": task_obj.agent,
                            "reason": "no handler registered",
                        }
                        task_obj.state = TaskState.FAILED
                except Exception as exc:
                    out = {"status": "failed", "agent": task_obj.agent, "error": str(exc)}
                    task_obj.state = TaskState.FAILED

                results["tasks"][task_obj.id] = out
                if task_obj.state == TaskState.FAILED:
                    results["failures"].append({"action": task_obj.action, **out})
                if isinstance(out, dict) and "findings" in out:
                    results["findings"].extend(out["findings"])

        max_rounds = len(graph.tasks) + 5
        rounds = 0
        while not graph.is_complete and rounds < max_rounds:
            ready = graph.ready_tasks
            if not ready:
                # Deadlock: pending tasks with unmet dependencies
                pending = [t for t in graph.tasks if t.state == TaskState.PENDING]
                for t in pending:
                    t.state = TaskState.FAILED
                    results["failures"].append(
                        {
                            "action": t.action,
                            "status": "blocked",
                            "reason": "dependency did not complete",
                        }
                    )
                break
            await asyncio.gather(*[run_task(t) for t in ready])
            rounds += 1

        return results
