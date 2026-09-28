"""Dual-memory architecture: persistent MEMORY vs runtime MEM."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any


class DualMemory:
    """Persistent + runtime memory with selective retrieval and promotion logic."""

    def __init__(self, persistent_path: str = "MEMORY.md", runtime_path: str = "MEM.md"):
        self._persistent_path = Path(persistent_path)
        self._runtime: dict[str, Any] = {}
        self._access_log: dict[str, int] = {}  # key → access count
        self._promotion_threshold = 3
        self._lock = asyncio.Lock()

    # --- Runtime (MEM) operations ---

    async def mem_set(self, key: str, value: Any) -> None:
        """Store in runtime memory."""
        async with self._lock:
            self._runtime[key] = {"value": value, "ts": time.time()}

    async def mem_get(self, key: str) -> Any:
        """Retrieve from runtime memory."""
        async with self._lock:
            entry = self._runtime.get(key)
            if entry:
                self._access_log[key] = self._access_log.get(key, 0) + 1
                return entry["value"]
        return None

    async def mem_clear(self) -> None:
        """Clear all runtime memory (end of session)."""
        async with self._lock:
            self._runtime.clear()

    # --- Persistent (MEMORY) operations ---

    def memory_query(self, scope: str) -> str:
        """Retrieve relevant section from persistent memory."""
        if not self._persistent_path.exists():
            return ""
        content = self._persistent_path.read_text()
        # Find section matching scope
        lines = content.split("\n")
        result = []
        in_section = False
        for line in lines:
            if line.startswith("## ") and scope.lower() in line.lower():
                in_section = True
                result.append(line)
            elif line.startswith("## ") and in_section:
                break
            elif in_section:
                result.append(line)
        return "\n".join(result) if result else ""

    def memory_append(self, section: str, content: str) -> None:
        """Append to persistent memory under a section."""
        if not self._persistent_path.exists():
            return
        current = self._persistent_path.read_text()
        marker = f"## {section}"
        if marker in current:
            # Append under existing section
            parts = current.split(marker)
            next_section = parts[1].find("\n## ")
            if next_section > 0:
                insert_point = len(parts[0]) + len(marker) + next_section
                updated = current[:insert_point] + f"\n- {content}" + current[insert_point:]
            else:
                updated = current + f"\n- {content}"
        else:
            updated = current + f"\n\n## {section}\n\n- {content}"
        self._persistent_path.write_text(updated)

    # --- Promotion/Discard logic ---

    async def check_promotions(self) -> list[str]:
        """Identify runtime entries that should be promoted to persistent memory."""
        promotable = []
        async with self._lock:
            for key, count in self._access_log.items():
                if count >= self._promotion_threshold:
                    promotable.append(key)
        return promotable

    async def promote(self, key: str, section: str = "Operational Learnings") -> None:
        """Promote a runtime entry to persistent memory."""
        value = await self.mem_get(key)
        if value is not None:
            self.memory_append(section, f"{key}: {value}")
            async with self._lock:
                self._access_log.pop(key, None)

    async def discard_stale(self, max_age_seconds: float = 3600) -> int:
        """Remove runtime entries older than max_age."""
        now = time.time()
        removed = 0
        async with self._lock:
            stale = [k for k, v in self._runtime.items() if now - v["ts"] > max_age_seconds]
            for k in stale:
                del self._runtime[k]
                removed += 1
        return removed

    # --- Selective retrieval ---

    async def get_context_for_agent(self, agent: str, scope: str = "") -> dict:
        """Get only relevant memory for a specific agent. Never full dump."""
        context: dict[str, Any] = {}
        if scope == "persistent":
            relevant = self.memory_query(agent)
            if relevant:
                context["persistent"] = relevant
        elif scope == "runtime":
            async with self._lock:
                # Only entries related to this agent
                context["runtime"] = {
                    k: v["value"]
                    for k, v in self._runtime.items()
                    if agent in k or k.startswith("shared_")
                }
        else:
            # Minimal: only shared runtime state
            async with self._lock:
                context["runtime"] = {
                    k: v["value"] for k, v in self._runtime.items() if k.startswith("shared_")
                }
        return context

    @property
    def runtime_size(self) -> int:
        return len(self._runtime)


class PersistentMemory:
    """In-memory key-value dictionary store for persistent findings."""

    def __init__(self):
        self._store: dict[str, Any] = {}

    def store(self, key: str, value: Any) -> None:
        self._store[key] = value

    def retrieve(self, key: str) -> Any:
        return self._store.get(key)
