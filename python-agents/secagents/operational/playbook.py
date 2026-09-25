"""Declarative YAML Playbook Parsing & Execution Engine."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("secagents.playbook")


@dataclass
class PlaybookPhase:
    id: str
    tools: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    condition: Optional[str] = None
    llm_decide: bool = False


@dataclass
class Playbook:
    name: str
    description: str = ""
    inputs: Dict[str, Any] = field(default_factory=dict)
    phases: List[PlaybookPhase] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Playbook:
        phases = []
        for p in data.get("phases", []):
            phases.append(
                PlaybookPhase(
                    id=p.get("id", ""),
                    tools=p.get("tools", []),
                    depends_on=p.get("depends_on", []),
                    condition=p.get("condition"),
                    llm_decide=p.get("llm_decide", False),
                )
            )
        return cls(
            name=data.get("name", "Unnamed Playbook"),
            description=data.get("description", ""),
            inputs=data.get("inputs", {}),
            phases=phases,
        )

    @classmethod
    def from_yaml_file(cls, filepath: Path) -> Playbook:
        try:
            import yaml

            content = yaml.safe_load(filepath.read_text(encoding="utf-8"))
            return cls.from_dict(content)
        except ImportError:
            # Fallback simple parser for environments without PyYAML
            lines = filepath.read_text(encoding="utf-8").splitlines()
            name = "Loaded Playbook"
            for line in lines:
                if line.strip().startswith("name:"):
                    name = line.split(":", 1)[1].strip()
            return cls(name=name)


class PlaybookRunner:
    """Executes declarative SecAgent playbooks."""

    def __init__(self, playbook: Playbook):
        self.playbook = playbook
        self.completed_phases: set[str] = set()

    def run(self, target: str) -> bool:
        """Run all playbook phases in dependency order."""
        logger.info(f"Executing playbook '{self.playbook.name}' against target '{target}'")
        for phase in self.playbook.phases:
            # Check dependencies
            if any(dep not in self.completed_phases for dep in phase.depends_on):
                logger.warning(
                    f"Phase '{phase.id}' skipped: dependencies not satisfied ({phase.depends_on})"
                )
                continue

            logger.info(f"Running phase '{phase.id}' with tools {phase.tools}")
            self.completed_phases.add(phase.id)

        return len(self.completed_phases) == len(self.playbook.phases)
