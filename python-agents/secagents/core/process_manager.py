"""ProcessManager: Real-time CLI subprocess monitoring and streaming engine."""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from typing import Any, Optional


class ProcessManager:
    """Manages system tool subprocess execution, timeout bounds, and output streaming."""

    def __init__(self) -> None:
        self.active_processes: dict[str, asyncio.subprocess.Process] = {}
        self.history: list[dict[str, Any]] = []

    async def run_command(
        self,
        command: list[str] | str,
        timeout: int = 120,
        cwd: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """Execute a tool command asynchronously with stream capture and timeouts."""
        cmd_str = command if isinstance(command, str) else " ".join(command)
        proc_id = f"proc_{int(time.time() * 1000)}"

        start_time = time.time()
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        try:
            if isinstance(command, str):
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                    env=merged_env,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                    env=merged_env,
                )

            self.active_processes[proc_id] = proc

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=float(timeout)
                )
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")
                returncode = proc.returncode or 0
            except asyncio.TimeoutError:
                proc.kill()
                stdout = ""
                stderr = f"Command timed out after {timeout} seconds"
                returncode = -1
            finally:
                self.active_processes.pop(proc_id, None)

            duration = round(time.time() - start_time, 2)
            result = {
                "proc_id": proc_id,
                "command": cmd_str,
                "returncode": returncode,
                "stdout": stdout,
                "stderr": stderr,
                "duration": duration,
                "success": returncode == 0,
            }
            self.history.append(result)
            return result

        except FileNotFoundError:
            return {
                "proc_id": proc_id,
                "command": cmd_str,
                "returncode": 127,
                "stdout": "",
                "stderr": f"Executable not found for command: {cmd_str}",
                "duration": round(time.time() - start_time, 2),
                "success": False,
            }
        except Exception as e:
            return {
                "proc_id": proc_id,
                "command": cmd_str,
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "duration": round(time.time() - start_time, 2),
                "success": False,
            }

    @staticmethod
    def check_binary(binary_name: str) -> Optional[str]:
        """Check if binary executable exists in PATH."""
        return shutil.which(binary_name)
