"""LLM Budget Guard and Token Cost Accounting Engine for SecAgent."""

from __future__ import annotations

import logging
import os

logger = logging.getLogger("secagents.budget_guard")

# Provider cost estimates per 1,000 tokens (USD)
TOKEN_PRICING = {
    "openai": {"prompt": 0.0025, "completion": 0.0100},
    "anthropic": {"prompt": 0.0030, "completion": 0.0150},
    "gemini": {"prompt": 0.0005, "completion": 0.0015},
    "groq": {"prompt": 0.0001, "completion": 0.0002},
    "openrouter": {"prompt": 0.0020, "completion": 0.0060},
    "default": {"prompt": 0.0020, "completion": 0.0060},
}


class BudgetGuard:
    """Real-time token cost accounting and safety limit enforcement."""

    def __init__(self, limit_usd: float | None = None):
        if limit_usd is None:
            env_val = os.environ.get("SECAGENT_PRICE_LIMIT", "10.0")
            try:
                limit_usd = float(env_val)
            except ValueError:
                limit_usd = 10.0
        self.limit_usd = limit_usd
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_cost_usd = 0.0

    def record_usage(
        self, prompt_tokens: int, completion_tokens: int, provider: str = "default"
    ) -> float:
        """Record token consumption and update accrued USD cost."""
        pricing = TOKEN_PRICING.get(provider.lower(), TOKEN_PRICING["default"])
        cost = (prompt_tokens / 1000.0) * pricing["prompt"] + (
            completion_tokens / 1000.0
        ) * pricing["completion"]

        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_cost_usd += cost

        logger.info(
            f"Recorded {prompt_tokens}+{completion_tokens} tokens ({provider}). Total cost: ${self.total_cost_usd:.4f}"
        )
        return cost

    def is_budget_exceeded(self) -> bool:
        """Return True if total USD cost exceeds configured price limit."""
        if self.limit_usd <= 0:  # 0 indicates unlimited budget
            return False
        return self.total_cost_usd >= self.limit_usd

    def summary(self) -> dict[str, float | int]:
        """Return budget consumption statistics."""
        return {
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "limit_usd": self.limit_usd,
            "exceeded": self.is_budget_exceeded(),
        }


# Singleton budget guard instance
global_budget_guard = BudgetGuard()
