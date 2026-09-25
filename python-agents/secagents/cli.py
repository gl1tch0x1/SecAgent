#!/usr/bin/env python3
"""
SecAgent CLI — Precision. Intelligence. Multi-Agent Mastery.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
    TaskProgressColumn,
)
from rich.text import Text
from rich.theme import Theme
from rich.box import ROUNDED, DOUBLE_EDGE

from secagents import __version__
from secagents.operational.integrity import check_and_apply_tool_update
from secagents.vault.env_loader import Vault
from secagents.pipeline.runner import ScanPipeline
from secagents.infra.preflight import run_preflight
from secagents.infra.scope import enforce_scope, ScopeViolationError
from secagents.agents.keyhacks import KeyhacksAgent
from secagents.whichllm.hardware import detect_hardware

# ─── Aesthetic Configuration ────────────────────────────────────────────────
custom_theme = Theme(
    {
        "info": "bold #00ffff",
        "warning": "bold #ffaa00",
        "error": "bold #ff003c",
        "success": "bold #00ff00",
        "critical": "bold white on #ff003c",
        "high": "bold #ff003c",
        "medium": "bold #ffaa00",
        "low": "bold #00ffff",
        "hacker": "bold #00ff00",
        "target": "bold #ff00ff",
        "dim": "grey50",
    }
)

console = Console(theme=custom_theme)

# ─── ASCII ARSENAL ───────────────────────────────────────────────────────────
BANNER = r"""
    _____           ___                    __
   / ___/___  _____/   | ____ ____  ____  / /______
   \__ \/ _ \/ ___/ /| |/ __ `/ _ \/ __ \/ __/ ___/
  ___/ /  __/ /__/ ___ / /_/ /  __/ / / / /_(__  )
 /____/\___/\___/_/  |_\__, /\___/_/ /_/_/   \___/
                      /____/
"""


def print_banner():
    banner_text = Text(BANNER, style="hacker")
    subtext = Text.from_markup(
        f"\n[bold white]» AUTONOMOUS OFFENSIVE INTELLIGENCE FRAMEWORK «[/]\n[dim]VERSION {__version__} | RED TEAM OPERATIONS[/]\n"
    )
    console.print(
        Panel(
            Group(banner_text, subtext),
            border_style="#00ff00",
            box=DOUBLE_EDGE,
            expand=False,
            padding=(1, 2),
        )
    )


# ─── Core Logic ─────────────────────────────────────────────────────────────


def _load_env() -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        Vault(Path(".env")).load()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secagent",
        description="SecAgent — Autonomous Offensive AI Framework (authorized testing only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"SecAgent {__version__}")

    sub = p.add_subparsers(dest="command", required=True)

    # Scan Command
    scan = sub.add_parser("scan", help="Execute autonomous red-team pipeline")
    scan.add_argument("--target", "-t", required=True, help="Target domain or root URL")
    scan.add_argument(
        "--depth",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Scan intensity and depth",
    )
    scan.add_argument("--workers", "-w", type=int, default=4, help="Parallel agent swarm size")
    scan.add_argument(
        "--skip-os-check", action="store_true", help="Bypass OS security baseline check"
    )
    scan.add_argument("--no-sandbox", action="store_true", help=argparse.SUPPRESS)
    scan.add_argument(
        "--max-requests", type=int, default=1000, help="Maximum built-in HTTP requests"
    )
    scan.add_argument("--rate-limit", type=float, default=5.0, help="Requests per second per host")
    scan.add_argument("--max-duration", type=float, default=900.0, help="Scan deadline in seconds")
    scan.add_argument(
        "--header-env",
        action="append",
        default=[],
        metavar="NAME",
        help="Environment variable containing one HTTP session header (Name: value)",
    )
    scan.add_argument(
        "--cookie-env",
        metavar="NAME",
        help="Environment variable containing the Cookie header value",
    )
    scan.add_argument("--api-spec", help="Local OpenAPI/Swagger JSON or YAML file")
    scan.add_argument("--har", action="append", default=[], help="Local HAR capture file")
    scan.add_argument(
        "--identity-contract",
        help="JSON file of read-only, two-identity proof cases; credentials come from environment variables",
    )
    scan.add_argument(
        "--state-contract",
        help="JSON file of opt-in state read, negative control, write and cleanup cases",
    )
    scan.add_argument(
        "--ssrf-contract",
        help="JSON file of GET SSRF probes using an approved operator-controlled OAST service",
    )
    scan.add_argument("--no-arsenal", action="store_true", help="Skip heuristic Arsenal probes")
    scan.add_argument("--insecure", action="store_true", help="Bypass SSL/TLS verification")
    scan.add_argument(
        "--setup-local-llm", action="store_true", help="Auto-provision local Ollama model"
    )
    scan.add_argument("--results-dir", default="cog-ai-results", help="Breach report directory")

    # Vault Command
    vault = sub.add_parser("vault", help="Interface with secret storage and API keys")
    vault.add_argument(
        "--validate", action="store_true", help="Probe key validity via live API calls"
    )
    vault.add_argument("--env", default=".env", help="Path to operational manifest")

    # Keyhacks Command
    keyhacks = sub.add_parser("keyhacks", help="Scan local assets for leaked credentials")
    keyhacks.add_argument("paths", nargs="+", help="Files or directories to audit")
    keyhacks.add_argument("--rate-limit", type=float, default=10.0, help="Max validations/min")

    # Infrastructure Commands
    sub.add_parser("preflight", help="Validate system readiness")
    sub.add_parser("update", help="Check and apply framework updates")
    sub.add_parser("hardware", help="Hardware-aware model optimization")
    sub.add_parser("worker", help="Start background workflow processor")

    # 150+ Tools Catalog Command
    tools = sub.add_parser("tools", help="Browse 150+ integrated security tools catalog")
    tools.add_argument("--category", "-c", help="Filter by tool category")

    # Cognitive Memory Command
    memory = sub.add_parser("memory", help="Inspect and query Aura Cognitive Memory")
    memory.add_argument("--target", "-t", help="Filter memory by target domain")
    memory.add_argument(
        "--purge-decay", action="store_true", help="Apply memory decay and purge stale patterns"
    )

    # 12 Specialized Agents Command
    sub.add_parser("agents", help="List 12 specialized AI swarm agents")

    # CTF Solver Workflow Command
    ctf_cmd = sub.add_parser("ctf", help="Execute CTF challenge solver pipeline")
    ctf_cmd.add_argument(
        "--category",
        choices=["web", "pwn", "crypto", "forensics"],
        default="web",
        help="CTF challenge category",
    )
    ctf_cmd.add_argument("--input", required=True, help="Target URL, binary, or challenge input")

    # MCP Server Command
    sub.add_parser("mcp", help="Run Model Context Protocol (MCP) JSON-RPC stdio server")

    # Playbook Command
    pb_cmd = sub.add_parser("playbook", help="Execute declarative YAML methodology playbook")
    pb_cmd.add_argument("file", help="Path to YAML playbook file")
    pb_cmd.add_argument("--target", "-t", required=True, help="Target domain or host")

    # Replay Proof Capsule Command
    rep_cmd = sub.add_parser("replay", help="Replay proof capsule PoC against target")
    rep_cmd.add_argument("capsule", help="Path to proof capsule JSON file")

    return p


async def cmd_scan(args: argparse.Namespace) -> int:
    if (
        args.workers <= 0
        or args.max_requests <= 0
        or args.rate_limit <= 0
        or args.max_duration <= 0
    ):
        console.print("[error]Workers and execution limits must be positive.[/error]")
        return 2
    if args.insecure:
        os.environ["SECAGENT_VERIFY_SSL"] = "false"

    try:
        domain = enforce_scope(args.target)
    except ScopeViolationError as e:
        console.print(f"[error]⛔ Scope Violation:[/error] {e}")
        return 2

    try:
        auth_headers: dict[str, str] = {}
        for name in args.header_env:
            raw = os.environ.get(name)
            if raw is None:
                raise ValueError(f"Session header variable {name} is not set")
            header_name, separator, header_value = raw.partition(":")
            if not separator or not re.fullmatch(r"[A-Za-z0-9-]+", header_name):
                raise ValueError(f"Session header variable {name} is malformed")
            if header_name.lower() in {"host", "content-length", "transfer-encoding", "connection"}:
                raise ValueError(f"Session header variable {name} uses a restricted header")
            if any(c in header_value for c in "\r\n"):
                raise ValueError(f"Session header variable {name} contains a line break")
            auth_headers[header_name] = header_value.strip()
        if args.cookie_env:
            cookie = os.environ.get(args.cookie_env)
            if cookie is None or any(c in cookie for c in "\r\n"):
                raise ValueError("Cookie environment variable is unset or invalid")
            auth_headers["Cookie"] = cookie
    except ValueError as exc:
        console.print(f"[error]Session configuration error:[/error] {exc}")
        return 2

    console.print(
        f"\n[bold magenta]󰋼[/bold magenta] [bold white]INITIATING OPERATION:[/bold white] [target]{args.target}[/target]"
    )
    console.print(f"[dim]Parameters: depth={args.depth}, workers={args.workers}[/dim]\n")

    pipeline = ScanPipeline(
        target=args.target,
        depth=args.depth,
        workers=args.workers,
        use_sandbox=False,
        skip_os_check=args.skip_os_check,
        setup_local_llm=args.setup_local_llm,
        results_dir=Path(args.results_dir),
        arsenal_secondary=not args.no_arsenal,
        max_requests=args.max_requests,
        requests_per_second_per_host=args.rate_limit,
        max_duration_seconds=args.max_duration,
        auth_headers=auth_headers,
        api_spec_path=Path(args.api_spec) if args.api_spec else None,
        har_paths=[Path(path) for path in args.har],
        identity_contract_path=Path(args.identity_contract) if args.identity_contract else None,
        state_contract_path=Path(args.state_contract) if args.state_contract else None,
        ssrf_contract_path=Path(args.ssrf_contract) if args.ssrf_contract else None,
    )

    try:
        with Progress(
            SpinnerColumn(spinner_name="dots", style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, complete_style="hacker", finished_style="success"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                description=f"Orchestrating agents against {domain}...", total=None
            )
            results = await pipeline.run()
            progress.update(task, completed=100)
    except Exception as e:
        console.print(f"[error]❌ Mission Failure:[/error] {e}")
        return 2

    findings: List[Dict[str, Any]] = results.get("findings", [])

    # Intelligence Summary
    table = Table(
        title="[bold white]MISSION INTELLIGENCE SUMMARY[/bold white]",
        show_header=True,
        header_style="bold cyan",
        box=ROUNDED,
        expand=True,
    )
    table.add_column("SEVERITY", justify="center", width=12)
    table.add_column("VULNERABILITY", justify="left")
    table.add_column("TARGET ENDPOINT", justify="left")
    table.add_column("CONFIDENCE", justify="center", width=10)

    for f in findings:
        sev = f.get("severity", "medium").lower()
        table.add_row(
            f"[{sev}]{sev.upper()}[/{sev}]",
            f.get("title", f.get("type", "Unknown")),
            f.get("url", f.get("endpoint", "N/A")),
            f"{int(float(f.get('confidence', 0)) * 100)}%",
        )

    console.print("\n")
    if findings:
        console.print(table)

        # Attack Chain visualization hint
        if results.get("chains"):
            console.print(
                Panel(
                    f"[bold yellow]⛓️ Attack Chains Detected:[/bold yellow] Found {len(results['chains'])} correlated exploit path(s).",
                    border_style="yellow",
                )
            )
    else:
        console.print(
            "[warning]No validated findings. This does not establish that the target is vulnerability-free.[/warning]"
        )

    if results.get("manual_leads"):
        console.print(
            f"[warning]{len(results['manual_leads'])} candidate(s) require manual or additional proof.[/warning]"
        )
    if results.get("phases", {}).get("armada_failures"):
        console.print(
            f"[error]{len(results['phases']['armada_failures'])} scan task(s) failed; coverage is incomplete.[/error]"
        )
    if results.get("budget", {}).get("termination_reason"):
        console.print(
            f"[error]Scan budget ended the run: {results['budget']['termination_reason']}; coverage is incomplete.[/error]"
        )

    console.print(
        f"\n[success]✅ OPERATION COMPLETE[/success] — {len(findings)} Validated Signal(s) Extracted."
    )

    if results.get("reports"):
        r_table = Table(box=None, padding=(0, 2))
        r_table.add_column("FORMAT", style="bold white")
        r_table.add_column("BREACH REPORT PATH", style="blue underline")
        for fmt, path in results["reports"].items():
            r_table.add_row(fmt.upper(), str(path))
        console.print(
            Panel(r_table, title="[bold white]DELIVERABLES[/bold white]", border_style="cyan")
        )

    return (
        2
        if (
            results.get("phases", {}).get("armada_failures")
            or results.get("budget", {}).get("termination_reason")
        )
        else 0
    )


async def cmd_vault(args: argparse.Namespace) -> int:
    v = Vault(env_path=Path(args.env))
    if args.validate:
        with console.status("[bold cyan]Probing operational keys for validity..."):
            await v.validate_all()
    else:
        v.load()
        from secagents.vault.env_loader import KeyReport, KeyStatus, mask_secret

        v.reports = []
        for name in (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GROQ_API_KEY",
            "DEEPSEEK_API_KEY",
            "LLM_API_KEYS",
        ):
            val = os.environ.get(name, "")
            status = KeyStatus.PRESENT if val else KeyStatus.MISSING
            v.reports.append(KeyReport(name, status, mask_secret(val) if val else ""))

    # Enhanced Vault Table
    table = Table(
        title="[bold white]OPERATIONAL MANIFEST STATUS[/bold white]", box=ROUNDED, expand=True
    )
    table.add_column("SERVICE", style="cyan")
    table.add_column("STATUS", justify="center")
    table.add_column("FRAGMENT", style="dim")

    from secagents.vault.env_loader import KeyStatus

    for r in v.reports:
        status_text = (
            "[green]ACTIVE[/green]"
            if r.status == KeyStatus.VALID
            else (
                "[red]MISSING[/red]"
                if r.status == KeyStatus.MISSING
                else (
                    "[yellow]REVOKED[/yellow]"
                    if r.status == KeyStatus.INVALID
                    else "[blue]PRESENT[/blue]"
                )
            )
        )
        table.add_row(r.name, status_text, r.masked)

    console.print(table)
    return 0


async def cmd_keyhacks(args: argparse.Namespace) -> int:
    agent = KeyhacksAgent(requests_per_minute=args.rate_limit)
    paths: list[str] = []
    for p in args.paths:
        path = Path(p)
        if path.is_dir():
            paths.extend(
                str(f)
                for f in path.rglob("*")
                if f.is_file()
                and not any(part in f.parts for part in (".git", ".venv", "node_modules"))
            )
        elif path.is_file():
            paths.append(str(path))

    if not paths:
        console.print("[warning]⚠ No assets found for auditing.[/warning]")
        return 0

    console.print(f"[info]󰋼[/info] Auditing {len(paths)} assets for leaked secrets...")
    with console.status("[bold yellow]Scanning assets..."):
        findings = await agent.scan_paths(paths[:1000])

    table = Table(title="LEAKED CREDENTIAL AUDIT", box=ROUNDED, expand=True)
    table.add_column("STATUS", justify="center", width=12)
    table.add_column("SERVICE")
    table.add_column("FRAGMENT")
    table.add_column("SOURCE ASSET", style="dim")

    for f in findings:
        status = (
            "[green]LIVE[/green]"
            if f.valid
            else ("[red]DEAD[/red]" if f.valid is False else "[yellow]UNKNOWN[/yellow]")
        )
        table.add_row(status, f.service, f.key_masked, f.source)

    if findings:
        console.print(table)
    else:
        console.print(
            Panel(
                "[success]✓ No leaked keys detected in local assets.[/success]",
                border_style="success",
            )
        )
    return 0


def main() -> None:
    _load_env()
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "scan":
            sys.exit(asyncio.run(cmd_scan(args)))
        elif args.command == "vault":
            sys.exit(asyncio.run(cmd_vault(args)))
        elif args.command == "keyhacks":
            sys.exit(asyncio.run(cmd_keyhacks(args)))
        elif args.command == "worker":
            from secagents.worker.runner import main as worker_main

            worker_main()
        elif args.command == "preflight":
            results = run_preflight()
            table = Table(title="SYSTEM PREFLIGHT DIAGNOSTICS", box=ROUNDED)
            table.add_column("CHECK")
            table.add_column("RESULT")
            for r in results:
                table.add_row(
                    r.name,
                    f"{'[green]PASS[/green]' if r.passed else '[red]FAIL[/red]'} — {r.message}",
                )
            console.print(table)
        elif args.command == "update":
            update_script = Path(__file__).parent.parent.parent / "update.py"
            if update_script.exists():
                subprocess.run([sys.executable, str(update_script)], check=False)
            else:
                with console.status("[bold magenta]Checking for framework updates..."):
                    _, msg = check_and_apply_tool_update()
                console.print(Panel(msg, title="UPDATE STATUS", border_style="magenta"))
        elif args.command == "hardware":
            profile = detect_hardware()
            console.print(
                Panel(
                    f"Hardware Summary: {profile.summary()}",
                    title="HARDWARE INTELLIGENCE",
                    border_style="cyan",
                )
            )
        elif args.command == "tools":
            from secagents.arsenal.registry import ToolRegistry

            table = Table(title="150+ SECURITY TOOLS ARSENAL CATALOG", box=ROUNDED, expand=True)
            table.add_column("KEY", style="bold cyan")
            table.add_column("TOOL NAME", style="bold white")
            table.add_column("CATEGORY", style="yellow")
            table.add_column("BINARY", style="dim")
            table.add_column("STATUS", justify="center")

            status = ToolRegistry.list_installed_tools()
            for key, meta in ToolRegistry.TOOLS_CATALOG.items():
                if args.category and args.category.lower() not in meta["category"].lower():
                    continue
                inst = "[green]INSTALLED[/green]" if status.get(key) else "[dim]AVAILABLE[/dim]"
                table.add_row(key, meta["name"], meta["category"], meta["binary"], inst)
            console.print(table)
        elif args.command == "memory":
            from secagents.core.aura_memory import AuraMemoryManager

            mem = AuraMemoryManager.get_instance()

            if args.purge_decay:
                purged = mem.apply_decay()
                console.print(
                    f"[success]✓ Memory decay applied: purged {purged} stale patterns.[/success]"
                )

            info = mem.inspect_memory(target=args.target)
            console.print(
                Panel(
                    f"SDK Active: {info['sdk_available']}\nDatabase: {info['database_path']}\nTargets DNA Count: {info['target_dna_count']}\nCognitive Patterns: {info['cognitive_patterns_count']}",
                    title="AURA COGNITIVE MEMORY STATUS",
                    border_style="cyan",
                )
            )

            if info["patterns"]:
                p_table = Table(title="CRYSTALLIZED COGNITIVE PATTERNS", box=ROUNDED, expand=True)
                p_table.add_column("TARGET", style="cyan")
                p_table.add_column("VULN TYPE", style="bold white")
                p_table.add_column("PAYLOAD", style="yellow")
                p_table.add_column("WAF BYPASSED", justify="center")
                p_table.add_column("CONFIDENCE", justify="center")

                for p in info["patterns"]:
                    p_table.add_row(
                        p["target"],
                        p["vuln_type"],
                        p["payload"][:40] + ("..." if len(p["payload"]) > 40 else ""),
                        "[green]YES[/green]" if p["waf_bypassed"] else "[dim]NO[/dim]",
                        f"{int(p['confidence'] * 100)}%",
                    )
                console.print(p_table)
        elif args.command == "agents":
            from secagents.agents.specialized import (
                IntelligentDecisionEngine,
                BugBountyWorkflowManager,
                CTFWorkflowManager,
                CVEIntelligenceManager,
                AIExploitGenerator,
                VulnerabilityCorrelator,
                TechnologyDetector,
                RateLimitDetector,
                FailureRecoverySystem,
                PerformanceMonitor,
                ParameterOptimizer,
                GracefulDegradation,
            )

            agents_list = [
                IntelligentDecisionEngine(),
                BugBountyWorkflowManager(),
                CTFWorkflowManager(),
                CVEIntelligenceManager(),
                AIExploitGenerator(),
                VulnerabilityCorrelator(),
                TechnologyDetector(),
                RateLimitDetector(),
                FailureRecoverySystem(),
                PerformanceMonitor(),
                ParameterOptimizer(),
                GracefulDegradation(),
            ]
            table = Table(title="12 SPECIALIZED AI SWARM AGENTS", box=ROUNDED, expand=True)
            table.add_column("AGENT NAME", style="bold cyan")
            table.add_column("CLASS", style="bold white")
            table.add_column("STATUS", justify="center", style="green")

            for ag in agents_list:
                table.add_row(ag.name, ag.__class__.__name__, "ACTIVE")
            console.print(table)
        elif args.command == "ctf":
            from secagents.agents.specialized import CTFWorkflowManager

            agent = CTFWorkflowManager()
            out = asyncio.run(agent.execute({"category": args.category, "input": args.input}))
            console.print(
                Panel(
                    f"CTF Solver Output:\n{out.result}",
                    title=f"CTF SOLVER — {args.category.upper()}",
                    border_style="green",
                )
            )
        elif args.command == "mcp":
            from secagents.mcp_server import MCPServer

            server = MCPServer()
            server.run_stdio()
        elif args.command == "playbook":
            from secagents.operational.playbook import Playbook, PlaybookRunner

            pb = Playbook.from_yaml_file(Path(args.file))
            runner = PlaybookRunner(pb)
            success = runner.run(args.target)
            msg = (
                "[success]✓ Playbook execution complete.[/success]"
                if success
                else "[error]❌ Playbook execution incomplete.[/error]"
            )
            console.print(Panel(msg, title=f"PLAYBOOK — {pb.name.upper()}", border_style="cyan"))
        elif args.command == "replay":
            from secagents.operational.proof_capsule import ProofCapsuleReplayer

            replayer = ProofCapsuleReplayer()
            ok, msg = replayer.replay_file(Path(args.capsule))
            border = "green" if ok else "yellow"
            console.print(
                Panel(msg, title="PROOF CAPSULE REPLAY VERIFICATION", border_style=border)
            )
    except KeyboardInterrupt:
        console.print("\n[warning]⚠ Mission aborted by operator.[/warning]")
        sys.exit(130)


if __name__ == "__main__":
    main()
