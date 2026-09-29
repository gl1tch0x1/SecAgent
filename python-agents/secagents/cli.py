#!/usr/bin/env python3
"""
SecAgent CLI — Precision. Intelligence. Multi-Agent Mastery.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sqlite3
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
from secagents.config import load_runtime_config
from secagents.infra.telemetry import MetricsCollector, configure_logging
from secagents.operational.integrity import check_tool_update
from secagents.vault.env_loader import Vault
from secagents.pipeline.runner import ScanPipeline
from secagents.infra.preflight import run_preflight
from secagents.infra.scope import enforce_scope, normalize_target, ScopeViolationError
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
   ____             __  ___   ____                 
  / __ \___  ___   / / / _ | / __/___  ____  ____ 
 / / / / _ \/ _ \ / / / __ |/ /_/ __ \/ __ \/ __ \
/ /_/ /  __/  __// / / /_/ / __/ /_/ / / / / /_/ /
\____/ \___|\___/_/  \____/_/  \____/_/_/ /_/ .___/
                                          /_/     
"""


def print_banner():
    banner_text = Text(BANNER, style="hacker")
    subtext = Text.from_markup(
        f"\n[bold white]SECAGENT // OFFENSIVE OPERATIONS CONSOLE[/]"
        f"\n[bold cyan]RECON[/] [dim]·[/] [bold magenta]VERIFY[/] [dim]·[/] [bold green]REPORT[/]"
        f"\n[dim]Version {__version__} | authorized security assessment workflow[/]\n"
    )
    console.print(
        Panel(
            Group(banner_text, subtext),
            border_style="#00ff66",
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
    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the runtime logging verbosity for the CLI",
    )
    p.add_argument(
        "--json-output",
        action="store_true",
        help="Emit structured JSON logs instead of plain text output",
    )

    sub = p.add_subparsers(dest="command", required=True)

    # Scan Command
    scan = sub.add_parser("scan", help="Execute autonomous red-team pipeline")
    scan_target = scan.add_mutually_exclusive_group(required=True)
    scan_target.add_argument("--target", "-t", help="Target domain or root URL")
    scan_target.add_argument(
        "--targets-file", help="UTF-8 file with one target domain or URL per line"
    )
    scan.add_argument(
        "--authorize-targets",
        action="store_true",
        help="Explicitly authorize the supplied targets for this command only",
    )
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
    scan.add_argument(
        "--fuzz-payloads", action="store_true", help="Try bounded encoded GET payload variants"
    )
    scan.add_argument(
        "--max-payload-variants",
        type=int,
        default=6,
        help="Variants per supported base payload (0-32)",
    )
    scan.add_argument(
        "--fuzz-cooldown-hours",
        type=float,
        default=24.0,
        help="Avoid repeating attempted variants for this many hours",
    )

    fuzz = sub.add_parser("fuzz", help="Fuzz local binary inputs or preview HTTP payload variants")
    fuzz_modes = fuzz.add_subparsers(dest="fuzz_mode", required=True)
    binary = fuzz_modes.add_parser("binary", help="Mutate a binary input file and compare outcomes")
    binary.add_argument("seed", help="Input file to mutate; the program itself is never modified")
    binary.add_argument("--program", help="Optional local parser or executable to test")
    binary.add_argument(
        "--arg",
        action="append",
        default=[],
        help="Program argument; {input} is replaced with the mutated file path",
    )
    binary.add_argument(
        "--allow-host-execution",
        action="store_true",
        help="Explicitly allow running the selected program on this host",
    )
    binary.add_argument(
        "--docker-image",
        help="Run the local parser inside an existing network-disabled Docker image",
    )
    binary.add_argument(
        "--collect-coverage",
        action="store_true",
        help="Read SECAGENT_COVERAGE_FILE written by an instrumented host program",
    )
    binary.add_argument(
        "--minimize-crashes", action="store_true", help="Try up to eight crash-reducing probes"
    )
    binary.add_argument("--runs", type=int, default=128, help="Maximum distinct mutations (1-5000)")
    binary.add_argument("--timeout", type=float, default=2.0, help="Seconds per program execution")
    binary.add_argument("--max-duration", type=float, default=300.0, help="Total fuzzing seconds")
    binary.add_argument("--max-input-bytes", type=int, default=1_048_576)
    binary.add_argument("--max-output-bytes", type=int, default=65_536)
    binary.add_argument("--max-saved-cases", type=int, default=20)
    binary.add_argument(
        "--mutation-seed", type=int, default=0, help="Reproducible mutation sequence seed"
    )
    binary.add_argument("--retry-after-hours", type=float, default=24.0)
    binary.add_argument("--results-dir", default="cog-ai-results/fuzz")
    payload = fuzz_modes.add_parser(
        "payload", help="Preview bounded variants for a supported check"
    )
    payload.add_argument("check", choices=["sqli", "xss", "ssti", "lfi"])
    payload.add_argument("seed", help="Base payload string")
    payload.add_argument("--max-variants", type=int, default=6)

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
    scope = sub.add_parser("scope", help="Manage the explicit scan target allowlist")
    scope.add_argument(
        "--add",
        action="append",
        metavar="DOMAIN",
        help="Authorize a domain; repeat or use comma-separated domains",
    )
    scope.add_argument(
        "--file", action="append", metavar="PATH", help="Import a UTF-8 list of authorized domains"
    )
    scope.add_argument("--list", action="store_true", help="Show the current allowlist")
    scope.add_argument("--env", default=".env", help="Path to the local configuration file")
    update = sub.add_parser("update", help="Check and safely apply main branch updates")
    update.add_argument(
        "--check-only", action="store_true", help="Report newer commits without changing files"
    )
    update.add_argument(
        "--reinstall", action="store_true", help="Verify installation even when current"
    )
    update.add_argument(
        "--allowed-domains", help="Pass explicit authorized domains to the installer"
    )
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


_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _valid_scope_domain(value: str) -> bool:
    host = value.removeprefix("*.")
    return bool(
        host
        and len(value) <= 253
        and all(_DOMAIN_LABEL.fullmatch(label) for label in host.split("."))
    )


def _read_target_lines(path: Path, *, max_entries: int = 100) -> list[str]:
    if path.stat().st_size > 1_048_576:
        raise ValueError("Target list exceeds the 1 MiB limit")
    entries = [
        line.strip()
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not entries or len(entries) > max_entries:
        raise ValueError(f"Target list must contain 1 to {max_entries} non-comment lines")
    return list(dict.fromkeys(entries))


def _authorize_for_command(targets: list[str]) -> None:
    domains = [
        item.strip() for item in os.environ.get("ALLOWED_DOMAINS", "").split(",") if item.strip()
    ]
    for target in targets:
        host = normalize_target(target)
        if host.startswith("*.") or not _valid_scope_domain(host):
            raise ValueError(f"Invalid target domain: {target}")
        if host not in domains:
            domains.append(host)
    previous = os.environ.get("ALLOWED_DOMAINS")
    os.environ["ALLOWED_DOMAINS"] = ",".join(domains)
    try:
        for target in targets:
            enforce_scope(target)
    except ScopeViolationError:
        if previous is None:
            os.environ.pop("ALLOWED_DOMAINS", None)
        else:
            os.environ["ALLOWED_DOMAINS"] = previous
        raise


async def cmd_scan_batch(args: argparse.Namespace) -> int:
    try:
        targets = _read_target_lines(Path(args.targets_file))
        if any(
            (
                args.header_env,
                args.cookie_env,
                args.identity_contract,
                args.state_contract,
                args.ssrf_contract,
            )
        ):
            raise ValueError(
                "Batch scans do not accept shared session or proof contracts; run those targets separately"
            )
        if args.authorize_targets:
            _authorize_for_command(targets)
        else:
            for target in targets:
                enforce_scope(target)
    except (OSError, UnicodeError, ValueError, ScopeViolationError) as exc:
        console.print(f"[error]Target list rejected:[/error] {exc}")
        return 2

    console.print(
        Panel(
            f"{len(targets)} scoped target(s) queued",
            title="[bold green]// BATCH MISSION //[/bold green]",
            border_style="green",
        )
    )
    failures = 0
    for index, target in enumerate(targets, 1):
        console.print(f"[bold cyan][{index}/{len(targets)}][/bold cyan] {target}")
        target_args = argparse.Namespace(**vars(args))
        target_args.target = target
        target_args.authorize_targets = False
        target_args.results_dir = str(Path(args.results_dir) / "batch" / normalize_target(target))
        if await cmd_scan(target_args):
            failures += 1
    console.print(
        Panel(
            f"{len(targets) - failures} completed / {failures} failed",
            title="BATCH SUMMARY",
            border_style="green" if not failures else "red",
        )
    )
    return 0 if not failures else 2


async def cmd_scan(args: argparse.Namespace) -> int:
    try:
        if getattr(args, "authorize_targets", False):
            _authorize_for_command([args.target])
        config = load_runtime_config(args)
    except (ValueError, ScopeViolationError) as exc:
        console.print(f"[error]Configuration error:[/error] {exc}")
        return 2

    args.workers = max(1, config.scan.workers)
    args.max_requests = max(1, config.scan.max_requests)
    args.rate_limit = max(0.1, config.scan.requests_per_second_per_host)
    args.max_duration = max(1.0, config.scan.max_duration_seconds)
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

    brief = Table.grid(padding=(0, 2))
    brief.add_column(style="bold cyan", min_width=12)
    brief.add_column(style="bold white")
    brief.add_row("TARGET", args.target)
    brief.add_row("PROFILE", f"{args.depth.upper()}  /  {args.workers} WORKERS")
    brief.add_row(
        "TRAFFIC CAP",
        f"{args.max_requests} REQUESTS  /  {args.rate_limit:g} RPS PER HOST  /  {args.max_duration:g}s",
    )
    brief.add_row("SCOPE LOCK", "[bold green]AUTHORIZED[/bold green]")
    console.print(
        Panel(
            brief,
            title="[bold green]// MISSION PARAMETERS //[/bold green]",
            subtitle="[dim]SCOPED EXECUTION[/dim]",
            border_style="green",
            expand=False,
        )
    )

    try:
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
            fuzz_payloads=args.fuzz_payloads,
            max_payload_variants=args.max_payload_variants,
            fuzz_cooldown_seconds=args.fuzz_cooldown_hours * 3600,
        )
    except ValueError as exc:
        console.print(f"[error]Scan configuration error:[/error] {exc}")
        return 2

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


def cmd_fuzz(args: argparse.Namespace) -> int:
    from secagents.operational.fuzzing import BinaryFuzzConfig, payload_variants, run_binary_fuzz

    try:
        if args.fuzz_mode == "payload":
            variants = payload_variants(
                args.check,
                {"method": "GET", "param": "q", "value": args.seed},
                args.max_variants,
            )
            console.print(json.dumps(variants, indent=2), markup=False)
            return 0
        from secagents.core.aura_memory import AuraMemoryManager

        results_dir = Path(args.results_dir)
        config = BinaryFuzzConfig(
            seed_path=Path(args.seed),
            results_dir=results_dir,
            program=Path(args.program) if args.program else None,
            program_args=tuple(args.arg),
            allow_host_execution=args.allow_host_execution,
            docker_image=args.docker_image,
            collect_coverage=args.collect_coverage,
            minimize_crashes=args.minimize_crashes,
            runs=args.runs,
            timeout_seconds=args.timeout,
            max_duration_seconds=args.max_duration,
            max_input_bytes=args.max_input_bytes,
            max_output_bytes=args.max_output_bytes,
            max_saved_cases=args.max_saved_cases,
            mutation_seed=args.mutation_seed,
            retry_after_seconds=args.retry_after_hours * 3600,
        )
        memory = AuraMemoryManager(db_path=results_dir / "aura-fuzz.db")
        report = run_binary_fuzz(config, memory)
        console.print(
            json.dumps(
                {"summary": report["summary"], "report_path": report["report_path"]}, indent=2
            ),
            markup=False,
        )
        return 0
    except (ValueError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
        console.print(f"[error]Fuzzing configuration or execution failed:[/error] {exc}")
        return 2


def cmd_scope(args: argparse.Namespace) -> int:
    """Persist an explicit operator-supplied scope without changing other secrets."""
    path = Path(args.env)
    try:
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        current = next(
            (line.partition("=")[2] for line in lines if line.startswith("ALLOWED_DOMAINS=")), ""
        )
        domains = [item.strip().lower() for item in current.split(",") if item.strip()]
        requested = [
            item.strip().lower() for group in (args.add or []) for item in group.split(",")
        ]
        for filename in args.file or []:
            requested.extend(
                item.strip().lower()
                for line in _read_target_lines(Path(filename), max_entries=1000)
                for item in line.split(",")
            )
        if len(requested) > 1000:
            raise ValueError("Scope import exceeds 1000 domains")
        if requested:
            if any(not _valid_scope_domain(item) for item in requested):
                raise ValueError(
                    "Use domain names or *.domain patterns without URLs or empty entries"
                )
            domains = list(dict.fromkeys([*domains, *requested]))
            lines = [line for line in lines if not line.startswith("ALLOWED_DOMAINS=")]
            lines.append("ALLOWED_DOMAINS=" + ",".join(domains))
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            os.environ["ALLOWED_DOMAINS"] = ",".join(domains)
            console.print(
                f"[success]Authorized {len(domains)} domain(s):[/success] {', '.join(domains)}"
            )
        if args.list or not requested:
            console.print(f"Authorized domains: {', '.join(domains) or '(none configured)'}")
    except (OSError, UnicodeError, ValueError) as exc:
        console.print(f"[error]Scope update failed:[/error] {exc}")
        return 2
    return 0


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
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "fuzz":
        configure_logging(args.log_level, args.json_output)
        sys.exit(cmd_fuzz(args))

    if args.command == "scope":
        sys.exit(cmd_scope(args))

    logger = configure_logging(args.log_level, args.json_output)
    metrics = MetricsCollector()
    metrics.increment("cli_invocations")
    logger.info(
        "secagent startup",
        extra={
            "event": "cli.start",
            "target": getattr(args, "target", ""),
            "log_level": args.log_level,
        },
    )

    print_banner()

    try:
        if args.command == "scan":
            sys.exit(asyncio.run(cmd_scan_batch(args) if args.targets_file else cmd_scan(args)))
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
                command = [sys.executable, str(update_script)]
                if args.check_only:
                    command.append("--check-only")
                if args.reinstall:
                    command.append("--reinstall")
                if args.allowed_domains:
                    command.extend(["--allowed-domains", args.allowed_domains])
                sys.exit(subprocess.run(command, check=False).returncode)
            else:
                with console.status("[bold magenta]Checking for framework updates..."):
                    release_status = check_tool_update()
                message = release_status.message
                if release_status.update_available:
                    message += "; update a source checkout with update.py"
                console.print(Panel(message, title="UPDATE STATUS", border_style="magenta"))
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
