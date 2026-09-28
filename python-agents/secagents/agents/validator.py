"""Conservative standalone finding review.

Live proof belongs to Crucible, which has typed policies and shared budgets.
Untrusted caller-provided proof cannot independently validate a finding.
"""

from secagents.agents.base import AgentConfig, AgentOutput, AgentRole, BaseAgent
from secagents.prompts import VALIDATOR_PROMPT


class ValidatorAgent(BaseAgent):
    """Preserve candidate findings as leads without manufacturing live proof."""

    def __init__(self) -> None:
        super().__init__(
            AgentConfig(
                role=AgentRole.VALIDATOR,
                name="validator",
                tools=[],
                timeout_seconds=300.0,
            )
        )

    def base_system_prompt(self) -> str:
        return VALIDATOR_PROMPT

    async def execute(self, task: dict) -> AgentOutput:
        findings = task.get("findings", [])
        if not isinstance(findings, list):
            return self._format_output(
                result={"error": "findings must be a list"},
                confidence=0.0,
                reasoning="Invalid finding input",
            )

        inconclusive = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            inconclusive.append(
                {
                    **finding,
                    "validated": False,
                    "validation_status": "manual_lead",
                    "validation_reason": "Live typed proof must be produced by Crucible",
                }
            )

        return self._format_output(
            result={
                "validated": [],
                "rejected": [],
                "inconclusive": inconclusive,
                "total": len(findings),
                "valid_count": 0,
            },
            confidence=1.0 if not findings else 0.0,
            reasoning=f"Reviewed {len(findings)} supplied findings",
        )
