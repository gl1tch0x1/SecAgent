"""Planner agent for strategy generation and task planning."""

import logging
from typing import Any

from secagents.agents.base import BaseAgent, AgentConfig, AgentOutput, AgentRole
from secagents.prompts import PLANNER_PROMPT

logger = logging.getLogger(__name__)


class PlannerAgent(BaseAgent):
    """Breaks objectives into executable task plans.

    Responsibilities:
    - Strategy generation based on objectives
    - Resource allocation to agents
    - Timeline planning
    - Risk assessment per task
    - Priority calculation
    """

    def __init__(self):
        super().__init__(
            AgentConfig(
                role=AgentRole.PLANNER,
                name="planner",
                tools=["scope_check", "task_decompose", "estimate_duration"],
                timeout_seconds=120.0,
            )
        )
        self.logger = logging.getLogger("secagents.planner")

    def base_system_prompt(self) -> str:
        """Return the planner's system prompt."""
        return PLANNER_PROMPT

    async def execute(self, task: dict) -> AgentOutput:
        """Execute planner logic to generate execution plan."""
        objective = task.get("objective", "")
        scope = task.get("scope", {})
        constraints = task.get("constraints", {})

        self.logger.info(f"Planning for objective: {objective}")

        try:
            # Validate scope
            if not self._validate_scope(scope):
                return self._format_output(
                    result={"error": "Invalid scope"},
                    confidence=0.0,
                    reasoning="Scope validation failed",
                )

            # Decompose into phases
            phases = self._plan(objective, scope, constraints)

            # Allocate resources
            resources = self._allocate_resources(phases)

            # Calculate timeline
            timeline = self._calculate_timeline(phases)

            # Assess risks
            risks = self._assess_risks(phases, scope)

            result = {
                "phases": phases,
                "resources": resources,
                "timeline": timeline,
                "risks": risks,
                "total_tasks": sum(len(p["tasks"]) for p in phases),
            }

            confidence = self._calculate_plan_confidence(result)

            self.logger.info(
                f"Generated plan with {len(phases)} phases, {result['total_tasks']} tasks"
            )

            return self._format_output(
                result=result,
                confidence=confidence,
                reasoning=f"Decomposed '{objective}' into {len(phases)} phases",
                metadata={
                    "objective": objective,
                    "scope_target": scope.get("target", ""),
                    "phase_count": len(phases),
                },
            )
        except Exception as e:
            self.logger.error(f"Planning failed: {str(e)}", exc_info=True)
            return self._format_output(
                result={"error": str(e)},
                confidence=0.0,
                reasoning="Planning execution failed",
            )

    def _validate_scope(self, scope: dict) -> bool:
        """Validate scope boundaries.

        Args:
            scope: Scope configuration

        Returns:
            True if scope is valid
        """
        required_fields = ["target"]
        valid = all(scope.get(field) for field in required_fields)

        if not valid:
            self.logger.warning("Scope validation failed: missing required fields")

        return valid

    def _plan(self, objective: str, scope: dict, constraints: dict) -> list[dict]:
        """Generate execution plan based on objective and scope.

        Args:
            objective: Security testing objective
            scope: Approved scope boundaries
            constraints: Execution constraints (time, resources, etc)

        Returns:
            List of phases with tasks
        """
        target = scope.get("target", "unknown")

        phases = [
            {
                "phase": "planning",
                "description": "Validate scope and create detailed plan",
                "priority": 1,
                "tasks": [
                    {
                        "agent": "planner",
                        "action": "validate_scope",
                        "target": target,
                        "estimated_duration": 5,
                    },
                ],
            },
            {
                "phase": "recon",
                "description": "Reconnaissance and attack surface discovery",
                "priority": 2,
                "tasks": [
                    {
                        "agent": "recon",
                        "action": "subdomain_enum",
                        "target": target,
                        "estimated_duration": 30,
                    },
                    {
                        "agent": "recon",
                        "action": "http_probe",
                        "target": target,
                        "estimated_duration": 20,
                    },
                    {
                        "agent": "recon",
                        "action": "crawl",
                        "target": target,
                        "estimated_duration": 25,
                    },
                ],
            },
            {
                "phase": "discovery",
                "description": "Endpoint and parameter discovery",
                "priority": 3,
                "tasks": [
                    {
                        "agent": "recon",
                        "action": "param_discovery",
                        "target": target,
                        "estimated_duration": 20,
                    },
                ],
            },
            {
                "phase": "testing",
                "description": "Vulnerability testing",
                "priority": 4,
                "tasks": [
                    {
                        "agent": "web_security",
                        "action": "scan",
                        "target": target,
                        "estimated_duration": 60,
                    },
                    {
                        "agent": "api_security",
                        "action": "scan",
                        "target": target,
                        "estimated_duration": 45,
                    },
                    {
                        "agent": "web3_security",
                        "action": "audit",
                        "target_path": target,  # Could be local source or remote
                        "estimated_duration": 40,
                    },
                ],
            },
            {
                "phase": "validation",
                "description": "Finding validation and false positive filtering",
                "priority": 5,
                "tasks": [
                    {
                        "agent": "validator",
                        "action": "validate_findings",
                        "estimated_duration": 30,
                    },
                ],
            },
            {
                "phase": "reporting",
                "description": "Report generation and documentation",
                "priority": 6,
                "tasks": [
                    {
                        "agent": "report",
                        "action": "generate",
                        "target": target,
                        "estimated_duration": 20,
                    },
                ],
            },
        ]

        self.logger.info(f"Generated plan with {len(phases)} phases")
        return phases

    def _allocate_resources(self, phases: list[dict]) -> dict:
        """Allocate resources to phases.

        Args:
            phases: List of phases

        Returns:
            Resource allocation
        """
        resources = {}
        for phase in phases:
            phase_name = phase["phase"]
            agent_actions: dict[str, list[str]] = {}

            for task in phase["tasks"]:
                agent = task["agent"]
                if agent not in agent_actions:
                    agent_actions[agent] = []
                agent_actions[agent].append(task["action"])

            resources[phase_name] = agent_actions

        self.logger.info(f"Allocated resources for {len(resources)} phases")
        return resources

    def _calculate_timeline(self, phases: list[dict]) -> dict:
        """Calculate timeline estimates.

        Args:
            phases: List of phases

        Returns:
            Timeline with durations
        """
        timeline: dict[str, Any] = {
            "phases": [],
            "total_duration_minutes": 0,
        }

        cumulative = 0
        for phase in phases:
            duration = sum(t.get("estimated_duration", 10) for t in phase["tasks"])
            cumulative += duration

            timeline["phases"].append(
                {
                    "phase": phase["phase"],
                    "duration_minutes": duration,
                    "start_minute": cumulative - duration,
                    "end_minute": cumulative,
                }
            )

        timeline["total_duration_minutes"] = cumulative

        self.logger.info(f"Calculated timeline: {cumulative} minutes total")
        return timeline

    def _assess_risks(self, phases: list[dict], scope: dict) -> list[dict]:
        """Assess risks for each phase.

        Args:
            phases: List of phases
            scope: Scope configuration

        Returns:
            Risk assessment for each phase
        """
        risks = []

        # Assess reconnaissance risks
        risks.append(
            {
                "phase": "recon",
                "risk": "Medium",
                "description": "Enumeration may trigger IDS/WAF",
                "mitigation": "Use throttled requests and rotate user agents",
            }
        )

        # Assess testing risks
        risks.append(
            {
                "phase": "testing",
                "risk": "High",
                "description": "Payload testing may cause DoS or data exfiltration",
                "mitigation": "Use sandboxed payloads and validate endpoint behavior first",
            }
        )

        # Assess scope violation risk
        in_scope = scope.get("endpoints", [])
        if not in_scope:
            risks.append(
                {
                    "phase": "all",
                    "risk": "Medium",
                    "description": "Undefined endpoint scope may lead to unauthorized testing",
                    "mitigation": "Request detailed endpoint list before testing",
                }
            )

        self.logger.info(f"Identified {len(risks)} risks")
        return risks

    def _calculate_plan_confidence(self, result: dict) -> float:
        """Calculate confidence in the plan.

        Args:
            result: Plan result

        Returns:
            Confidence score 0.0-1.0
        """
        if "error" in result:
            return 0.0

        phases = result.get("phases", [])
        total_tasks = result.get("total_tasks", 0)

        base_confidence = 0.75

        # Increase confidence with more phases (better decomposition)
        phase_factor = min(len(phases) / 6.0, 1.0) * 0.15

        # Increase confidence with more detailed tasks
        task_factor = min(total_tasks / 10.0, 1.0) * 0.1

        confidence = base_confidence + phase_factor + task_factor

        return round(min(confidence, 1.0), 2)
