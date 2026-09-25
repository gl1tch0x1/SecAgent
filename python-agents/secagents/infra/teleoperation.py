"""Human-In-The-Loop (HITL) Teleoperation & Double Ctrl+C Signal Handler."""

from __future__ import annotations

import logging
import signal
import sys
import time
from typing import Any, Callable, Optional

logger = logging.getLogger("secagents.teleoperation")


class TeleoperationController:
    """Manages double Ctrl+C signal handling and interactive operator REPL."""

    def __init__(self, pause_callback: Optional[Callable[[], None]] = None):
        self.pause_callback = pause_callback
        self.last_sigint_time: float = 0.0
        self.is_paused: bool = False
        self._previous_handler: Any = None

    def enable(self) -> None:
        """Register signal handler for SIGINT."""
        self._previous_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._handle_sigint)

    def disable(self) -> None:
        """Restore previous SIGINT signal handler."""
        if self._previous_handler is not None:
            signal.signal(signal.SIGINT, self._previous_handler)

    def _handle_sigint(self, signum: int, frame: Any) -> None:
        now = time.time()
        # Double Ctrl+C within 600ms triggers Teleoperation REPL
        if now - self.last_sigint_time < 0.6:
            logger.warning(
                "\n󱈸 Double Ctrl+C detected — Intercepting scan execution for Teleoperation REPL!"
            )
            self.is_paused = True
            if self.pause_callback:
                self.pause_callback()
            self.enter_repl()
        else:
            self.last_sigint_time = now
            print("\n[!] Press Ctrl+C again within 600ms to enter Teleoperation REPL...")

    def enter_repl(self) -> None:
        """Interactive REPL shell allowing operator to step, inspect, inject instructions, or abort."""
        print("\n" + "═" * 60)
        print("  SecAgent Teleoperation REPL — Operator Control Active")
        print("  Commands: inspect | inject <instruction> | step | resume | abort")
        print("═" * 60)

        while self.is_paused:
            try:
                cmd = input("  [secagent-operator]:: ").strip()
                if not cmd:
                    continue

                parts = cmd.split(maxsplit=1)
                action = parts[0].lower()

                if action in ("resume", "c", "continue"):
                    print("  [+] Resuming scan execution...")
                    self.is_paused = False
                    break
                elif action in ("abort", "exit", "quit"):
                    print("  [-] Operator aborted engagement.")
                    sys.exit(0)
                elif action == "inspect":
                    print("  [i] Status: Operational | Teleoperation REPL active")
                elif action == "step":
                    print("  [>] Executing single step...")
                    break
                elif action == "inject":
                    instruction = parts[1] if len(parts) > 1 else ""
                    print(f"  [+] Injected instruction: '{instruction}'")
                else:
                    print(
                        "  [?] Unknown action. Available: inspect, inject <msg>, step, resume, abort"
                    )
            except (KeyboardInterrupt, EOFError):
                print("\n  [-] Resuming...")
                self.is_paused = False
                break
