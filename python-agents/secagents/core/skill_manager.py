"""Skill Manager to load and provide advanced hunting strategies."""

import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class SkillManager:
    """Manages global and modular security skills and instructions."""

    _instance = None
    _global_skills: str = ""
    _modular_skills: Dict[str, str] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SkillManager, cls).__new__(cls)
            cls._instance._load_all_skills()
        return cls._instance

    def _load_all_skills(self):
        """Load all skills from SKILL.md files recursively."""
        try:
            pkg_root = Path(__file__).resolve().parent.parent.parent.parent
            root_paths = [
                pkg_root / "SKILL.md",
                Path("SKILL.md").resolve(),
            ]

            for path in root_paths:
                if path.exists():
                    logger.info(f"SkillManager: Loading global skills from {path.absolute()}")
                    self._global_skills = path.read_text(encoding="utf-8")
                    break

            # 2. Load Modular Skills from skills/ directory
            skills_dirs = [
                pkg_root / "skills",
                Path("skills").resolve(),
            ]
            skills_dir = next((d for d in skills_dirs if d.exists()), None)

            if skills_dir and skills_dir.exists():
                logger.info(f"SkillManager: Discovering modular skills in {skills_dir.absolute()}")
                for skill_path in skills_dir.rglob("SKILL.md"):
                    skill_name = skill_path.parent.name
                    logger.info(
                        f"SkillManager: Loading modular skill '{skill_name}' from {skill_path}"
                    )
                    self._modular_skills[skill_name] = skill_path.read_text(encoding="utf-8")

        except Exception as e:
            logger.error(f"SkillManager: Failed to load skills: {str(e)}")

    @property
    def skills(self) -> str:
        """Get all loaded skill content (global + modular)."""
        all_skills = [self._global_skills]
        for name, content in self._modular_skills.items():
            all_skills.append(f"### Modular Skill: {name}\n{content}")
        return "\n\n".join(filter(None, all_skills)) or "No advanced skills loaded."

    def get_skill(self, name: str) -> Optional[str]:
        """Get a specific modular skill by name."""
        return self._modular_skills.get(name)

    def apply_to_prompt(self, base_prompt: str, skill_name: Optional[str] = None) -> str:
        """Append relevant skills to a prompt."""
        prompt = base_prompt

        # Always add global skills
        if self._global_skills:
            prompt += "\n\n=== ADVANCED HUNTING SKILLS (GLOBAL) ===\n"
            prompt += self._global_skills
            prompt += "\n===============================\n"

        # Add specific skill if requested
        if skill_name and skill_name in self._modular_skills:
            prompt += f"\n\n=== MODULE SKILL: {skill_name} ===\n"
            prompt += self._modular_skills[skill_name]
            prompt += "\n===============================\n"

        return prompt

    async def notify_invocation(self, skill_name: str, action: str):
        """Trigger mandatory voice notification if applicable."""
        if not skill_name:
            logger.warning("Notification attempted without a valid skill name")
            return

        try:
            import httpx

            message = f"Running the {skill_name} workflow in the SecAgents system to {action}"
            async with httpx.AsyncClient(timeout=0.5) as client:
                response = await client.post("http://localhost:8888/notify", json={"message": message})
                response.raise_for_status()
        except Exception as exc:
            logger.warning(
                "Failed to notify workflow invocation for '%s' action '%s': %s",
                skill_name,
                action,
                exc,
            )


# Global singleton
skill_manager = SkillManager()
