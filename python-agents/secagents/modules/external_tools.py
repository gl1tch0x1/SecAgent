"""Bounded, shell-free wrappers for optional security tools."""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass

from secagents.infra.scope import enforce_scope
from secagents.infra.execution_budget import ExecutionBudget


@dataclass
class ToolResult:
    tool: str
    success: bool
    output: list[str]
    raw: str = ""


class ExternalTools:
    """Invoke known binaries without passing a target through a shell."""

    TOOLS = {
        "subfinder",
        "httpx",
        "naabu",
        "katana",
        "waybackurls",
        "nuclei",
        "arjun",
        "ffuf",
        "ghauri",
        "nomore403",
    }

    @staticmethod
    def available() -> dict[str, bool]:
        return {name: shutil.which(name) is not None for name in ExternalTools.TOOLS}

    @staticmethod
    async def run(
        tool: str,
        target: str,
        timeout: int = 120,
        budget: ExecutionBudget | None = None,
        **kwargs,
    ) -> ToolResult:
        if tool not in ExternalTools.TOOLS:
            return ToolResult(tool, False, [], f"Unknown tool: {tool}")
        binary = shutil.which(tool)
        if not binary:
            return ToolResult(tool, False, [], f"{tool} not installed")
        try:
            enforce_scope(target)
        except PermissionError as exc:
            return ToolResult(tool, False, [], f"Scope violation: {exc}")
        if budget is not None:
            return ToolResult(
                tool,
                False,
                [],
                "Skipped: external tool HTTP traffic cannot be counted or scope-checked by the shared budget",
            )

        args: dict[str, list[str]] = {
            "subfinder": ["-d", target, "-silent"],
            "httpx": ["-u", target, "-silent", "-status-code", "-tech-detect"],
            "naabu": ["-host", target, "-top-ports", "100", "-silent", "-json"],
            "katana": ["-u", target, "-silent", "-jc", "-d", "3"],
            "waybackurls": [],
            "nuclei": ["-u", target, "-severity", "medium,high,critical", "-json"],
            "arjun": ["-u", target, "--stable", "-oJ", "-"],
            "ghauri": ["-u", target, "--batch", "--level", "2"],
            "nomore403": ["-u", target],
        }
        if tool == "ffuf":
            wordlist = kwargs.get("wordlist")
            if not wordlist:
                return ToolResult(tool, False, [], "wordlist is required")
            args[tool] = [
                "-u",
                target.rstrip("/") + "/FUZZ",
                "-w",
                str(wordlist),
                "-mc",
                "200,301,302",
                "-s",
            ]

        try:
            proc = await asyncio.create_subprocess_exec(
                binary,
                *args[tool],
                stdin=asyncio.subprocess.PIPE if tool == "waybackurls" else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdin = (target + "\n").encode() if tool == "waybackurls" else None
            stdout, stderr = await asyncio.wait_for(proc.communicate(stdin), timeout=timeout)
            output = stdout.decode(errors="replace")
            error = stderr.decode(errors="replace")
            return ToolResult(
                tool,
                proc.returncode == 0,
                [line for line in output.splitlines() if line],
                output if proc.returncode == 0 else error[:1000],
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ToolResult(tool, False, [], "Timeout")
        except OSError as exc:
            return ToolResult(tool, False, [], str(exc))

    @staticmethod
    async def run_parallel(
        tools: list[str], target: str, budget: ExecutionBudget | None = None
    ) -> dict[str, ToolResult]:
        results = await asyncio.gather(
            *(ExternalTools.run(tool, target, budget=budget) for tool in tools),
            return_exceptions=True,
        )
        return {
            name: result
            if isinstance(result, ToolResult)
            else ToolResult(name, False, [], str(result))
            for name, result in zip(tools, results)
        }
