"""Operational audit trail for security decisions and policy enforcement."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class AuditEvent:
    """Single immutable audit record describing a policy or runtime decision."""

    event: str
    operation: str
    allowed: bool
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


class AuditLogger:
    """Simple structured logger for policy and runtime audit events."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None

    def record(self, event: AuditEvent) -> None:
        payload = event.to_json()
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(payload)
                fh.write("\n")

    def record_decision(
        self,
        *,
        operation: str,
        allowed: bool,
        reason: str,
        event: str = "policy_decision",
        **metadata: Any,
    ) -> None:
        self.record(
            AuditEvent(
                event=event,
                operation=operation,
                allowed=allowed,
                reason=reason,
                metadata=dict(metadata),
            )
        )
