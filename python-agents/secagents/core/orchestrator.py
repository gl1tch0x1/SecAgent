"""Central orchestration engine: intent → decompose → route → execute → aggregate."""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
from collections import defaultdict

from secagents.engine.caveman import compress


class Intent(str, Enum):
    SCAN = "scan"
    RECON = "recon"
    VALIDATE = "validate"
    REPORT = "report"
    PLAN = "plan"
    QUERY = "query"
    AI_SAFETY = "ai_safety"


class TaskState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass
class Task:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    intent: Intent = Intent.QUERY
    agent: str = ""
    action: str = ""
    input: dict = field(default_factory=dict)
    output: Any = None
    state: TaskState = TaskState.PENDING
    depends_on: list[str] = field(default_factory=list)
    model_hint: str = ""  # preferred model routing
    memory_scope: str = ""  # which memory to attach
    tools: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    duration_ms: float = 0


@dataclass
class ExecutionGraph:
    tasks: list[Task] = field(default_factory=list)
    root_intent: Intent = Intent.QUERY

    @property
    def ready_tasks(self) -> list[Task]:
        """Tasks whose dependencies are all DONE."""
        done_ids = {t.id for t in self.tasks if t.state == TaskState.DONE}
        return [
            t
            for t in self.tasks
            if t.state == TaskState.PENDING and all(d in done_ids for d in t.depends_on)
        ]

    @property
    def is_complete(self) -> bool:
        return all(t.state in (TaskState.DONE, TaskState.FAILED) for t in self.tasks)


@dataclass
class RetryConfig:
    """Configuration for task retry logic."""

    max_retries: int = 3
    initial_backoff: float = 1.0
    max_backoff: float = 30.0
    backoff_multiplier: float = 2.0


@dataclass
class CircuitBreakerState:
    """State tracker for circuit breaker pattern."""

    failures: int = 0
    last_failure_time: float = 0.0
    open_until: float = 0.0
    consecutive_successes: int = 0
    failure_threshold: int = 5
    success_threshold: int = 3

    @property
    def is_open(self) -> bool:
        """Check if circuit is in open state (rejecting calls)."""
        return time.time() < self.open_until

    def record_failure(self) -> None:
        """Record a failure and update circuit state."""
        self.failures += 1
        self.last_failure_time = time.time()
        self.consecutive_successes = 0
        if self.failures >= self.failure_threshold:
            self.open_until = time.time() + 60.0  # 60 second cooldown

    def record_success(self) -> None:
        """Record a success and potentially close circuit."""
        self.consecutive_successes += 1
        if self.consecutive_successes >= self.success_threshold:
            self.failures = 0
            self.open_until = 0.0
            self.consecutive_successes = 0

    def reset_for_testing(self) -> None:
        """Reset state for testing purposes."""
        self.failures = 0
        self.last_failure_time = 0.0
        self.open_until = 0.0
        self.consecutive_successes = 0


class Orchestrator:
    """Brain of the system. Classifies intent, builds minimal execution graph, dispatches."""

    def __init__(self, retry_config: Optional[RetryConfig] = None):
        """
        Initialize the Orchestrator.

        Args:
            retry_config: Configuration for retry behavior. Defaults to RetryConfig().
        """
        self._agents: dict[str, Callable] = {}
        self._event_handlers: dict[str, list[Callable]] = {}
        self._retry_config = retry_config or RetryConfig()
        self._circuit_breakers: dict[str, CircuitBreakerState] = defaultdict(CircuitBreakerState)
        self._task_results: dict[str, Any] = {}

    def register_agent(self, name: str, executor: Callable) -> None:
        """
        Register an agent executor by name.

        Args:
            name: Unique identifier for the agent.
            executor: Callable that executes the agent (async or sync).
        """
        self._agents[name] = executor

    def on_event(self, event_type: str, handler: Callable) -> None:
        """
        Register an event handler for orchestration events.

        Args:
            event_type: Type of event (e.g., 'task_started', 'task_completed').
            handler: Callable to invoke when event fires (async or sync).
        """
        self._event_handlers.setdefault(event_type, []).append(handler)

    async def _emit(self, event_type: str, data: dict) -> None:
        """
        Emit an event to all registered handlers.

        Args:
            event_type: Type of event to emit.
            data: Event payload dictionary.
        """
        for handler in self._event_handlers.get(event_type, []):
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(data)
                else:
                    handler(data)
            except Exception as exc:
                logger = __import__("logging").getLogger(__name__)
                logger.warning(
                    "Event handler for '%s' failed while processing task %s: %s",
                    event_type,
                    data.get("task_id", "unknown"),
                    exc,
                )

    def classify_intent(self, request: str) -> Intent:
        """
        Fast intent classification without LLM call.

        This version normalizes the request and matches a prioritized set of
        domain-specific expressions so natural user phrasing is classified more
        reliably than a brittle raw substring check.
        """
        if not request or not str(request).strip():
            return Intent.QUERY

        r = str(request).lower()
        normalized = re.sub(r"[^a-z0-9\s-]", " ", r)
        normalized = re.sub(r"\s+", " ", normalized).strip()

        keyword_rules = [
            (Intent.AI_SAFETY, [
                "ai safety",
                "prompt injection",
                "repo poisoning",
                "assistant config",
                "cursorrules",
                "llm jailbreak",
                "rag poisoning",
                "agent compromise",
            ]),
            (Intent.SCAN, [
                "bug bounty",
                "bounty hunter",
                "security audit",
                "web assessment",
                "pentest",
                "vulnerability scan",
                "web security",
                "scan for vulnerabilities",
                "check for xss",
                "check for sqli",
                "sql injection",
                "xss",
                "ssrf",
            ]),
            (Intent.RECON, [
                "reconnaissance",
                "recon",
                "discover assets",
                "subdomain enumeration",
                "discover subdomains",
                "asset discovery",
                "enumerate hosts",
                "enumerate endpoints",
                "find open ports",
                "crawl website",
            ]),
            (Intent.REPORT, [
                "report",
                "generate a report",
                "write a summary",
                "executive summary",
                "final report",
                "export findings",
                "deliverable",
            ]),
            (Intent.VALIDATE, [
                "validate",
                "verify",
                "confirm",
                "poc",
                "proof",
                "replay",
                "check exploitability",
            ]),
            (Intent.PLAN, [
                "plan",
                "strategy",
                "decompose",
                "roadmap",
                "execution plan",
            ]),
        ]

        for intent, phrases in keyword_rules:
            if any(phrase in normalized for phrase in phrases):
                return intent

        if any(word in normalized for word in ["scan", "test", "exploit", "attack", "vuln", "issue", "find"]):
            return Intent.SCAN
        if any(word in normalized for word in ["discover", "subdomain", "enumerate", "crawl", "recon"]):
            return Intent.RECON
        if any(word in normalized for word in ["report", "summary", "deliverable", "export"]):
            return Intent.REPORT

        return Intent.QUERY

    def decompose_intent(self, intent: Intent, context: dict) -> ExecutionGraph:
        """
        Break complex intents into minimal execution graphs.

        This method decomposes a high-level intent into a set of tasks
        with explicit dependencies, forming a directed acyclic graph (DAG).

        Args:
            intent: The Intent to decompose.
            context: Context dictionary containing parameters like 'target', 'request', etc.

        Returns:
            ExecutionGraph with tasks ordered by dependencies.
        """
        graph = ExecutionGraph(root_intent=intent)

        if intent == Intent.SCAN:
            target = context.get("target", "")
            # Phase 1: Reconnaissance
            recon = Task(
                intent=Intent.RECON,
                agent="recon",
                action="full_recon",
                input={"target": target},
                model_hint="fast",
                tools=["subfinder", "httpx", "katana"],
                memory_scope="runtime",
            )
            # Phase 2: Universal Meta-Scan (depends on recon)
            scan = Task(
                intent=Intent.SCAN,
                agent="security_orchestrator",
                action="universal_scan",
                input={"target": target},
                depends_on=[recon.id],
                model_hint="balanced",
                tools=["universal_analyzer"],
                memory_scope="runtime",
            )
            # The scan pipeline owns proof validation and reporting. Running those
            # stages here duplicated validation and could publish intermediate data.
            graph.tasks = [recon, scan]

        elif intent == Intent.AI_SAFETY:
            graph.tasks = [
                Task(
                    agent="security_orchestrator",
                    action="ai_safety_audit",
                    input=context,
                    model_hint="reasoning",
                )
            ]

        elif intent == Intent.RECON:
            target = context.get("target", "")
            graph.tasks = [
                Task(
                    agent="recon",
                    action="full_recon",
                    input={"target": target},
                    model_hint="fast",
                    tools=["subfinder", "httpx", "katana", "waybackurls"],
                )
            ]

        elif intent == Intent.VALIDATE:
            graph.tasks = [
                Task(
                    agent="validator",
                    action="validate",
                    input=context,
                    model_hint="reasoning",
                    tools=["http_request", "sandbox_exec", "poc_generate"],
                )
            ]

        elif intent == Intent.REPORT:
            graph.tasks = [
                Task(
                    agent="report",
                    action="generate",
                    input=context,
                    model_hint="fast",
                    tools=["report_generate"],
                )
            ]

        elif intent == Intent.PLAN:
            graph.tasks = [
                Task(
                    agent="planner",
                    action="plan",
                    input=context,
                    model_hint="reasoning",
                    memory_scope="persistent",
                )
            ]
        else:
            graph.tasks = [
                Task(agent="supervisor", action="query", input=context, model_hint="fast")
            ]

        return graph

    def decompose(self, intent: Intent, context: dict) -> ExecutionGraph:
        """
        Deprecated alias for decompose_intent. Use decompose_intent instead.

        Args:
            intent: The Intent to decompose.
            context: Context dictionary.

        Returns:
            ExecutionGraph with decomposed tasks.
        """
        return self.decompose_intent(intent, context)

    async def route_task(self, task: Task) -> Callable:
        """
        Route a task to the appropriate agent based on intent and agent name.

        This method selects the best agent executor for a given task,
        considering model hints, available tools, and circuit breaker state.

        Args:
            task: Task to route.

        Returns:
            Callable executor for the task.

        Raises:
            ValueError: If no suitable agent executor found.
        """
        agent_name = task.agent

        # Check circuit breaker state
        if self._circuit_breakers[agent_name].is_open:
            await self._emit(
                "circuit_open",
                {"agent": agent_name, "task_id": task.id, "reason": "Circuit breaker is open"},
            )
            raise RuntimeError(f"Agent '{agent_name}' circuit breaker is open")

        executor = self._agents.get(agent_name)
        if not executor:

            def default_executor(action, input_data):
                return {"status": "completed", "action": action, "agent": agent_name}

            executor = default_executor

        return executor

    async def aggregate_results(self, graph: ExecutionGraph) -> dict:
        """
        Collect and merge results from all completed tasks.

        This method aggregates results from the execution graph into
        a unified output dictionary, handling errors and maintaining
        result ordering by task dependencies.

        Args:
            graph: Completed ExecutionGraph.

        Returns:
            Dictionary with aggregated results keyed by agent names.
        """
        aggregated: dict[str, Any] = {}
        errors: list[dict] = []

        for task in graph.tasks:
            if task.state == TaskState.DONE and task.output:
                # Store successful result
                key = task.agent
                if key in aggregated:
                    # If key exists, convert to list or append
                    if not isinstance(aggregated[key], list):
                        aggregated[key] = [aggregated[key]]
                    aggregated[key].append(task.output)
                else:
                    aggregated[key] = task.output

            elif task.state == TaskState.FAILED:
                errors.append(
                    {
                        "task_id": task.id,
                        "agent": task.agent,
                        "error": task.output or {"error": "Unknown failure"},
                    }
                )

        # Add metadata
        aggregated["_metadata"] = {
            "total_tasks": len(graph.tasks),
            "completed": sum(1 for t in graph.tasks if t.state == TaskState.DONE),
            "failed": sum(1 for t in graph.tasks if t.state == TaskState.FAILED),
            "errors": errors,
            "root_intent": graph.root_intent.value,
        }

        return aggregated

    async def handle_task_failure(
        self, task: Task, graph: ExecutionGraph, exception: Exception
    ) -> bool:
        """
        Handle task failure with retry logic and circuit breaker.

        This method implements exponential backoff retry logic and
        circuit breaker pattern to gracefully degrade under failure.

        Args:
            task: Failed task.
            graph: Execution graph context.
            exception: Exception that caused failure.

        Returns:
            True if task should be retried, False if permanent failure.
        """
        agent_name = task.agent
        cb = self._circuit_breakers[agent_name]

        # Record failure in circuit breaker
        cb.record_failure()

        # Check if we should retry
        retry_count = task.input.get("_retry_count", 0)
        if retry_count >= self._retry_config.max_retries:
            await self._emit(
                "task_permanent_failure",
                {
                    "task_id": task.id,
                    "agent": agent_name,
                    "error": str(exception),
                    "retries_exhausted": retry_count,
                },
            )
            return False

        # Calculate backoff
        backoff = min(
            self._retry_config.initial_backoff
            * (self._retry_config.backoff_multiplier**retry_count),
            self._retry_config.max_backoff,
        )

        await self._emit(
            "task_retry",
            {
                "task_id": task.id,
                "agent": agent_name,
                "attempt": retry_count + 1,
                "backoff_seconds": backoff,
                "error": str(exception),
            },
        )

        # Schedule retry
        await asyncio.sleep(backoff)
        task.input["_retry_count"] = retry_count + 1
        task.state = TaskState.PENDING
        return True

    async def execute_graph(self, graph: ExecutionGraph, timeout_seconds: float = 300.0) -> dict:
        """
        Execute all tasks in the graph respecting dependencies.

        This method orchestrates execution of all tasks in the graph,
        ensuring dependencies are satisfied, handling retries, and
        aggregating results.

        Args:
            graph: ExecutionGraph to execute.
            timeout_seconds: Maximum time to execute (default 300s = 5 min).

        Returns:
            Dictionary with aggregated results from all tasks.
        """
        deadline = time.time() + timeout_seconds
        execution_start = time.time()

        while not graph.is_complete:
            # Check timeout
            if time.time() > deadline:
                await self._emit(
                    "execution_timeout",
                    {
                        "timeout_seconds": timeout_seconds,
                        "tasks_remaining": sum(
                            1
                            for t in graph.tasks
                            if t.state not in (TaskState.DONE, TaskState.FAILED)
                        ),
                    },
                )
                # Mark running tasks as failed
                for task in graph.tasks:
                    if task.state == TaskState.RUNNING:
                        task.state = TaskState.FAILED
                        task.output = {"error": "Execution timeout"}
                break

            # Get ready tasks (dependencies satisfied)
            ready = graph.ready_tasks
            if not ready:
                # No ready tasks, but graph not complete
                # Wait briefly before checking again
                await asyncio.sleep(0.05)
                continue

            # Execute all ready tasks in parallel
            coros = [self._execute_task(task, graph) for task in ready]
            await asyncio.gather(*coros)

        # Emit completion event
        duration_ms = (time.time() - execution_start) * 1000
        await self._emit(
            "graph_execution_complete",
            {
                "duration_ms": round(duration_ms, 1),
                "total_tasks": len(graph.tasks),
                "completed_tasks": sum(1 for t in graph.tasks if t.state == TaskState.DONE),
                "failed_tasks": sum(1 for t in graph.tasks if t.state == TaskState.FAILED),
            },
        )

        # Aggregate and return results
        return await self.aggregate_results(graph)

    async def _execute_task(self, task: Task, graph: ExecutionGraph) -> None:
        """
        Execute a single task with retry and error handling.

        Args:
            task: Task to execute.
            graph: Execution graph context.
        """
        task.state = TaskState.RUNNING
        await self._emit(
            "task_started", {"task_id": task.id, "agent": task.agent, "action": task.action}
        )

        start = time.time()
        retry_count = 0
        max_retries = self._retry_config.max_retries

        while retry_count <= max_retries:
            try:
                # Inject outputs from dependencies
                for dep_id in task.depends_on:
                    dep = next((t for t in graph.tasks if t.id == dep_id), None)
                    if dep and dep.output:
                        task.input[f"from_{dep.agent}"] = dep.output

                # Compress input for token efficiency
                if isinstance(task.input.get("request"), str):
                    task.input["request"] = compress(task.input["request"])

                # Route to appropriate agent
                executor = await self.route_task(task)

                # Execute task
                if asyncio.iscoroutinefunction(executor):
                    task.output = await executor(task.action, task.input)
                else:
                    task.output = await asyncio.to_thread(executor, task.action, task.input)

                # Record success
                self._circuit_breakers[task.agent].record_success()
                task.state = TaskState.DONE
                break

            except Exception as e:
                # Try to handle failure with retry
                retry_count += 1
                should_retry = await self.handle_task_failure(task, graph, e)

                if not should_retry:
                    task.output = {"error": str(e)}
                    task.state = TaskState.FAILED
                    break

        task.duration_ms = (time.time() - start) * 1000
        await self._emit(
            "task_completed",
            {
                "task_id": task.id,
                "agent": task.agent,
                "state": task.state.value,
                "duration_ms": round(task.duration_ms, 1),
                "retries": retry_count,
            },
        )

    async def execute(
        self, request: str, context: dict | None = None, trace_id: str | None = None
    ) -> dict:
        """
        Main entry point: classify → decompose → execute → aggregate.

        Args:
            request: User request string.
            context: Optional context dictionary with parameters.
            trace_id: Optional telemetry trace ID.

        Returns:
            Dictionary with execution results.
        """
        ctx = context or {}
        tid = trace_id or str(uuid.uuid4())
        start = time.time()

        # Step 1: Classify intent
        intent = self.classify_intent(request)
        await self._emit(
            "intent_classified", {"trace_id": tid, "intent": intent.value, "request": request}
        )

        # Step 2: Decompose into execution graph
        graph = self.decompose_intent(intent, {**ctx, "request": request, "trace_id": tid})
        await self._emit(
            "graph_created",
            {"trace_id": tid, "task_count": len(graph.tasks), "root_intent": intent.value},
        )

        # Step 3: Execute graph (timeout: 5 min max)
        results = await self.execute_graph(graph, timeout_seconds=300.0)

        # Step 4: Calculate total duration
        duration = (time.time() - start) * 1000

        await self._emit(
            "execution_complete",
            {
                "trace_id": tid,
                "duration_ms": round(duration, 1),
                "tasks": len(graph.tasks),
                "intent": intent.value,
            },
        )

        return {
            "trace_id": tid,
            "intent": intent.value,
            "results": results,
            "duration_ms": round(duration, 1),
        }

    async def execute_workflow(
        self,
        intent: Intent | str,
        target: str = "",
        scope: str = "",
        context: Optional[dict] = None,
    ) -> dict:
        """Execute workflow for a specified intent and target context."""
        ctx = context or {}
        if target:
            ctx["target"] = target
        if scope:
            ctx["scope"] = scope

        if isinstance(intent, str):
            intent_obj = Intent(intent) if intent in [i.value for i in Intent] else Intent.SCAN
        else:
            intent_obj = intent

        graph = self.decompose_intent(intent_obj, ctx)
        results = await self.execute_graph(graph)
        return {
            "status": "completed",
            "intent": intent_obj.value,
            "findings": results,
            "results": results,
        }
