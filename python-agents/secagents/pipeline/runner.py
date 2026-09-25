"""Unified scan pipeline: scope, discovery, scanning, proof, and reporting."""

from __future__ import annotations

import os
from pathlib import Path
from rich.console import Console

from secagents.operational.integrity import check_os_security_updates, OS_UPDATE_MESSAGE
from secagents.whichllm.hardware import detect_hardware, setup_ollama
from secagents.armada.swarm import ArmadaOrchestrator
from secagents.armada.handlers import build_scan_handlers
from secagents.arsenal.exploits import ArsenalScanner
from secagents.crucible.validation import CrucibleValidator
from secagents.crucible.regression import RegressionRegistry
from secagents.remediation.patcher import AutoPatcher
from secagents.remediation.reporter import ReportGenerator
from secagents.hermes.retrospective import RetrospectiveAgent
from secagents.hermes.store import HermesMemory
from secagents.engine.ci_notifier import CINotifier
from secagents.infra.scope import enforce_scope, ScopeViolationError
from secagents.infra.execution_budget import ExecutionBudget
from secagents.infra.request_inventory import import_har, import_openapi
from secagents.infra.browser_discovery import discover_browser
from secagents.intel.shodan_client import ShodanIntel
from secagents.intel.chaos_client import ChaosIntel
from secagents.crucible.identity_proof import load_identity_contracts, prove_identity
from secagents.crucible.state_contract import load_state_contracts, observe_state_contract
from secagents.crucible.oast_proof import load_ssrf_contracts, prove_ssrf


class ScanPipeline:
    """Bounded scan pipeline with scope enforcement and deterministic checks."""

    def __init__(
        self,
        target: str,
        depth: str = "standard",
        workers: int = 4,
        use_sandbox: bool = True,
        skip_os_check: bool = False,
        setup_local_llm: bool = False,
        results_dir: Path | None = None,
        arsenal_secondary: bool = True,
        max_requests: int = 1000,
        requests_per_second_per_host: float = 5.0,
        max_duration_seconds: float = 900.0,
        auth_headers: dict[str, str] | None = None,
        api_spec_path: Path | None = None,
        har_paths: list[Path] | None = None,
        identity_contract_path: Path | None = None,
        state_contract_path: Path | None = None,
        ssrf_contract_path: Path | None = None,
    ):
        self.target = target
        self.depth = depth
        self.workers = workers
        self.use_sandbox = use_sandbox
        self.skip_os_check = skip_os_check
        self.setup_local_llm = setup_local_llm
        self.results_dir = results_dir or Path(os.environ.get("RESULTS_DIR", "cog-ai-results"))
        self.arsenal_secondary = arsenal_secondary
        self.auth_headers = auth_headers or {}
        self.api_spec_path = api_spec_path
        self.har_paths = har_paths or []
        self.identity_contract_path = identity_contract_path
        self.state_contract_path = state_contract_path
        self.ssrf_contract_path = ssrf_contract_path
        self.budget = ExecutionBudget(
            max_requests=max_requests,
            requests_per_second_per_host=requests_per_second_per_host,
            max_concurrency=workers,
            max_duration_seconds=max_duration_seconds,
        )
        self.results: dict = {"target": target, "phases": {}, "findings": [], "chains": []}
        self.console = Console()

    async def run(self) -> dict:
        # 0. Scope gate (fail-closed)
        try:
            domain = enforce_scope(self.target)
            self.results["domain"] = domain
        except ScopeViolationError as e:
            self.console.print(f"[bold red]⛔ Scope Violation:[/bold red] {e}")
            raise ScopeViolationError(str(e)) from e

        # 1. Pre-flight
        ok, msg = check_os_security_updates(skip=self.skip_os_check)
        if not ok:
            self.console.print(f"[bold red]CRITICAL:[/bold red] {OS_UPDATE_MESSAGE}")
            raise RuntimeError(OS_UPDATE_MESSAGE)
        self.results["phases"]["preflight"] = {"os_check": msg}

        # 2. Optional local model provisioning. Proof is deterministic and
        # does not depend on an API key or an LLM opinion.
        from secagents.core.skill_manager import skill_manager

        if skill_manager.skills:
            self.console.print(
                "[bold green]🔥[/bold green] [white]Advanced Hunting Skills loaded from SKILL.md[/white]"
            )

        if self.setup_local_llm:
            hw = detect_hardware()
            self.console.print(f"  [cyan]Hardware:[/cyan] {hw.summary()}")
            _, ollama_msg = setup_ollama(pull=True)
            self.console.print(f"  [cyan]whichllm:[/cyan] {ollama_msg}")

        # Fortress is not an isolation boundary for the Python scan path.
        self.results["phases"]["runtime"] = {"status": "host_execution"}

        # 4. External intel
        self.console.print(
            "[bold blue]󰋼[/bold blue] [white]Extracting external intelligence...[/white]"
        )
        intel: dict = {}
        providers: dict[str, str] = {}
        shodan = ShodanIntel(budget=self.budget)
        chaos = ChaosIntel(budget=self.budget)
        if shodan.available:
            try:
                intel["shodan_dns"] = await shodan.search_domain(domain)
                providers["shodan"] = "completed"
            except Exception as exc:
                providers["shodan"] = f"failed: {type(exc).__name__}"
        else:
            providers["shodan"] = "skipped: API key unavailable"
        if chaos.available:
            try:
                intel["chaos_subdomains"] = await chaos.subdomains(domain)
                providers["chaos"] = "completed"
            except Exception as exc:
                providers["chaos"] = f"failed: {type(exc).__name__}"
        else:
            providers["chaos"] = "skipped: API key unavailable"
        self.results["phases"]["external_intel"] = providers
        self.results["intel"] = intel

        templates = []
        if self.api_spec_path:
            templates.extend(
                import_openapi(
                    self.api_spec_path,
                    self.target if "://" in self.target else f"https://{domain}/",
                )
            )
        for path in self.har_paths:
            templates.extend(import_har(path))
        self.results["phases"]["api_inventory"] = {
            "imported_templates": len(templates),
            "read_templates_scanned": sum(t.method == "GET" for t in templates),
            "other_methods_retained_not_sent": sum(t.method != "GET" for t in templates),
        }

        browser_result = await discover_browser(
            self.target if "://" in self.target else f"https://{domain}/",
            self.budget,
            max_depth=0 if self.depth == "quick" else 1 if self.depth == "standard" else 2,
            max_pages=5 if self.depth == "quick" else 10 if self.depth == "standard" else 20,
            auth_headers=self.auth_headers,
        )
        self.results["phases"]["browser_discovery"] = {
            key: value
            for key, value in browser_result.items()
            if key not in {"urls", "form_templates"}
        }
        self.results["phases"]["browser_discovery"]["urls_discovered"] = len(
            browser_result.get("urls", [])
        )

        # 5. The Armada — execute full DAG
        self.console.print(
            "[bold blue]󰋼[/bold blue] [white]Deploying agent swarm (The Armada)...[/white]"
        )
        shared: dict = {
            "target": domain,
            "target_url": self.target if "://" in self.target else f"https://{domain}/",
            "depth": self.depth,
            "intel": intel,
            "raw_findings": [],
            "endpoints": [self.target if "://" in self.target else f"https://{domain}/"]
            + [t.url for t in templates if t.method == "GET"]
            + browser_result.get("urls", []),
            "request_templates": templates,
            "budget": self.budget,
            "auth_headers": self.auth_headers,
        }
        armada = ArmadaOrchestrator(workers=self.workers)
        for name, handler in build_scan_handlers(shared).items():
            armada.register_handler(name, handler)

        graph = armada.plan_mission(domain, self.depth)
        armada_results = await armada.execute(graph, shared)
        self.results["phases"]["armada_failures"] = armada_results.get("failures", [])
        raw_findings = list(armada_results.get("findings", [])) or shared.get("raw_findings", [])

        self.results["phases"]["armada"] = {
            "tasks": len(graph.tasks),
            "task_results": len(armada_results.get("tasks", {})),
            "specialists": [s.name for s in armada.hire_specialists(graph)],
        }

        # Secondary: Arsenal heuristic probes
        if self.arsenal_secondary and not armada_results.get("failures"):
            self.console.print(
                "[bold blue]󰋼[/bold blue] [white]Engaging secondary heuristic probes (The Arsenal)...[/white]"
            )
            scanner = ArsenalScanner(
                verify_ssl=os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false",
                budget=self.budget,
                auth_headers=self.auth_headers,
            )
            endpoints = shared.get("endpoints") or [f"https://{domain}"]
            limit = 25 if self.depth == "quick" else 50 if self.depth == "standard" else 100
            for url in endpoints[:limit]:
                for p in await scanner.scan_url(url):
                    raw_findings.append(
                        {
                            "title": f"{p.vuln_type.upper()} in {p.parameter}",
                            "type": p.vuln_type,
                            "vuln_type": p.vuln_type,
                            "url": p.url,
                            "parameter": p.parameter,
                            "payload": p.payload,
                            "evidence": p.evidence,
                            "proof_signal": p.evidence,
                            "severity": "medium",
                            "confidence": p.confidence,
                            "source": "arsenal",
                            "deterministic": False,
                        }
                    )

        # Deduplicate
        seen: set[str] = set()
        unique: list[dict] = []
        for f in raw_findings:
            identity_url = (
                f.get("poc_url") or f.get("url")
                if (f.get("payload_spec") or {}).get("method") == "GET_PATH"
                else f.get("url")
            )
            key = "|".join(
                [str(identity_url)]
                + [
                    str(f.get(field, ""))
                    for field in (
                        "type",
                        "vuln_type",
                        "request_method",
                        "parameter",
                        "payload",
                        "proof_signal",
                    )
                ]
            )
            if key not in seen:
                seen.add(key)
                unique.append(f)

        # 6. The Crucible
        self.console.print(
            "[bold blue]󰋼[/bold blue] [white]Validating signals and correlating chains (The Crucible)...[/white]"
        )
        crucible = CrucibleValidator(budget=self.budget, auth_headers=self.auth_headers)
        try:
            outcomes = await crucible.validate_batch(unique)
            identity_contracts = (
                load_identity_contracts(self.identity_contract_path)
                if self.identity_contract_path
                else []
            )
            for contract in identity_contracts:
                try:
                    outcomes.append(await prove_identity(contract, self.budget))
                except Exception as exc:
                    outcomes.append(
                        {
                            "title": "Cross-identity private resource exposure",
                            "check_key": "idor",
                            "url": contract.owner_url,
                            "validated": False,
                            "validation_status": "inconclusive",
                            "validation_reason": f"Identity proof could not complete: {type(exc).__name__}",
                        }
                    )
            self.results["phases"]["identity_proof"] = {
                "contracts": len(identity_contracts),
                "validated": sum(
                    item.get("validated", False)
                    for item in outcomes
                    if item.get("check_key") == "idor"
                ),
            }
            state_contracts = (
                load_state_contracts(self.state_contract_path) if self.state_contract_path else []
            )
            for state_contract in state_contracts:
                try:
                    outcomes.append(await observe_state_contract(state_contract, self.budget))
                except Exception as exc:
                    outcomes.append(
                        {
                            "title": "Operator-contracted API state change",
                            "url": state_contract.write_url,
                            "validated": False,
                            "validation_status": "inconclusive",
                            "validation_reason": f"State contract could not complete: {type(exc).__name__}",
                        }
                    )
            self.results["phases"]["state_proof"] = {
                "contracts": len(state_contracts),
                "cleanup_failures": sum(
                    bool((item.get("proof") or {}).get("cleanup_failed")) for item in outcomes
                ),
            }
            ssrf_contracts = (
                load_ssrf_contracts(self.ssrf_contract_path) if self.ssrf_contract_path else []
            )
            for ssrf_contract in ssrf_contracts:
                try:
                    outcomes.append(
                        await prove_ssrf(ssrf_contract, self.budget, auth_headers=self.auth_headers)
                    )
                except Exception as exc:
                    outcomes.append(
                        {
                            "title": "Server-side request to operator callback",
                            "check_key": "ssrf",
                            "url": ssrf_contract.probe_url,
                            "validated": False,
                            "validation_status": "inconclusive",
                            "validation_reason": f"OAST proof could not complete: {type(exc).__name__}",
                        }
                    )
            self.results["phases"]["ssrf_proof"] = {
                "contracts": len(ssrf_contracts),
                "validated": sum(
                    item.get("validated", False)
                    for item in outcomes
                    if item.get("check_key") == "ssrf"
                ),
            }
            validated = [f for f in outcomes if f.get("validated")]
            self.results["findings"] = validated
            self.results["manual_leads"] = [
                f for f in outcomes if f.get("validation_status") in ("manual_lead", "inconclusive")
            ]
            self.results["rejected_candidates"] = (
                len(outcomes) - len(validated) - len(self.results["manual_leads"])
            )
            self.results["chains"] = await crucible.correlate_chains(validated)
        finally:
            await crucible.aclose()

        registry = RegressionRegistry(self.results_dir / "regression")
        for f in validated:
            registry.register(f)

        # 6b. Crystallize Cognitive Memory Signals
        from secagents.core.aura_memory import AuraMemoryManager, TargetDNA

        memory = AuraMemoryManager.get_instance()

        # Remember Target DNA
        clean_domain = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        memory.remember_target_dna(
            TargetDNA(
                target=self.target,
                domain=clean_domain,
                tech_stack=list(self.results.get("intel", {}).get("technologies", [])),
                rate_limit_detected=any(
                    f.get("type") == "missing_rate_limiting" for f in validated
                ),
                recommended_concurrency=10 if len(validated) < 5 else 5,
            )
        )

        # Crystallize validated findings into Cognitive Memory
        for f in validated:
            if isinstance(f, dict) and f.get("severity") in ["critical", "high", "medium"]:
                memory.crystallize_pattern(
                    target=self.target,
                    vuln_type=f.get("vuln_type") or f.get("type", "unknown"),
                    payload=f.get("payload", ""),
                    waf_bypassed=f.get("waf_bypassed", False),
                    confidence=f.get("confidence", 0.9),
                    metadata={"location": f.get("location"), "cwe": f.get("cwe")},
                )

        # 7. Remediation
        self.console.print(
            "[bold blue]󰋼[/bold blue] [white]Generating breach reports and auto-patches...[/white]"
        )
        patcher = AutoPatcher()
        patcher.apply_to_findings(validated)
        reporter = ReportGenerator(self.results_dir / "reports")
        self.results["budget"] = self.budget.snapshot()
        report_paths = reporter.generate_all(
            domain,
            validated,
            self.results["chains"],
            manual_leads=self.results["manual_leads"],
            coverage={
                "armada_failures": self.results["phases"]["armada_failures"],
                "armada_tasks": self.results["phases"]["armada"],
                "external_tools": [
                    v.get("external_tools", {})
                    for v in armada_results.get("tasks", {}).values()
                    if isinstance(v, dict) and v.get("external_tools")
                ],
                "skipped_stateful_checks": sum(
                    v.get("skipped_stateful_checks", 0)
                    for v in armada_results.get("tasks", {}).values()
                    if isinstance(v, dict)
                ),
                "skipped_callback_checks": sum(
                    v.get("skipped_callback_checks", 0)
                    for v in armada_results.get("tasks", {}).values()
                    if isinstance(v, dict)
                ),
                "budget": self.results["budget"],
                "api_inventory": self.results["phases"]["api_inventory"],
                "browser_discovery": self.results["phases"]["browser_discovery"],
                "browser_form_templates": len(browser_result.get("form_templates", [])),
                "candidate_urls": sum(
                    v.get("candidate_urls", 0)
                    for v in armada_results.get("tasks", {}).values()
                    if isinstance(v, dict)
                ),
                "urls_truncated": sum(
                    v.get("urls_truncated", 0)
                    for v in armada_results.get("tasks", {}).values()
                    if isinstance(v, dict)
                ),
            },
        )
        self.results["reports"] = report_paths

        notifier = CINotifier()
        if report_paths.get("markdown"):
            await notifier.notify_slack(validated, report_paths["markdown"])
            await notifier.create_jira_tickets(validated)

        # 8. Hermes
        self.console.print(
            "[bold blue]󰋼[/bold blue] [white]Archiving mission data to persistent memory...[/white]"
        )
        hermes = HermesMemory(self.results_dir / "hermes" / "memory.db")
        retro = RetrospectiveAgent(hermes)
        self.results["hermes"] = retro.analyze(self.results)
        hermes.export_json(self.results_dir / "hermes" / "export.json")

        return self.results
