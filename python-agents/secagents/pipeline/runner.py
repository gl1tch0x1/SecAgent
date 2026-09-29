"""Unified scan pipeline: scope, discovery, scanning, proof, and reporting."""

from __future__ import annotations

import os
import hashlib
from pathlib import Path
from typing import Callable
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
from secagents.infra.security_policy import SecurityPolicy
from secagents.infra.execution_budget import ExecutionBudget
from secagents.infra.request_inventory import import_har, import_openapi
from secagents.infra.browser_discovery import discover_browser
from secagents.infra.scan_contracts import (
    EvidenceRecord,
    PhaseContract,
    PhaseResult,
    ProofArtifact,
    ScanContext,
    validate_phase_contract,
)
from secagents.intel.shodan_client import ShodanIntel
from secagents.intel.chaos_client import ChaosIntel
from secagents.crucible.identity_proof import load_identity_contracts, prove_identity
from secagents.crucible.state_contract import load_state_contracts, observe_state_contract
from secagents.crucible.oast_proof import load_ssrf_contracts, prove_ssrf
from secagents.core.aura_memory import AuraMemoryManager


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
        fuzz_payloads: bool = False,
        max_payload_variants: int = 6,
        fuzz_cooldown_seconds: float = 86400.0,
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
        self.security_policy = SecurityPolicy.from_env(
            contracted_write=state_contract_path is not None,
            contracted_ssrf=ssrf_contract_path is not None,
        )
        if not 0 <= max_payload_variants <= 32 or fuzz_cooldown_seconds < 0:
            raise ValueError("Invalid payload fuzzing limits")
        self.fuzz_payloads = fuzz_payloads
        self.max_payload_variants = max_payload_variants
        self.fuzz_cooldown_seconds = fuzz_cooldown_seconds
        self.budget = ExecutionBudget(
            max_requests=max_requests,
            requests_per_second_per_host=requests_per_second_per_host,
            max_concurrency=workers,
            max_duration_seconds=max_duration_seconds,
        )
        self.results: dict = {"target": target, "phases": {}, "findings": [], "chains": []}
        self.on_progress: Callable[[str, str], None] | None = None
        self.console = Console()
        self.context = ScanContext(
            target=target,
            domain=target if "//" not in target else target.split("//", 1)[1].split("/", 1)[0],
            depth=depth,
            workers=workers,
            results_dir=str(self.results_dir),
            max_requests=max_requests,
            requests_per_second_per_host=requests_per_second_per_host,
            max_duration_seconds=max_duration_seconds,
            auth_headers=self.auth_headers,
            api_spec_path=str(api_spec_path) if api_spec_path else None,
            har_paths=[str(p) for p in (har_paths or [])],
            identity_contract_path=str(identity_contract_path) if identity_contract_path else None,
            state_contract_path=str(state_contract_path) if state_contract_path else None,
            ssrf_contract_path=str(ssrf_contract_path) if ssrf_contract_path else None,
            fuzz_payloads=fuzz_payloads,
            max_payload_variants=max_payload_variants,
            fuzz_cooldown_seconds=fuzz_cooldown_seconds,
        )

    def _progress(self, stage: str, state: str) -> None:
        if self.on_progress is not None:
            try:
                self.on_progress(stage, state)
            except Exception:
                pass  # Display failures must not change scan results.

    def _record_phase(
        self,
        name: str,
        payload: dict,
        evidence: list[EvidenceRecord] | None = None,
        contract: PhaseContract | None = None,
    ) -> PhaseResult:
        result = PhaseResult(name=name, payload=payload, evidence=evidence or [])
        if contract is not None:
            validate_phase_contract(result, contract)

        self.results["phases"][name] = payload
        entries: list[dict] = []
        if evidence:
            entries = [
                {
                    "phase": e.phase,
                    "kind": e.kind,
                    "url": e.url,
                    "method": e.method,
                    "status_code": e.status_code,
                    "payload": e.payload,
                    "proof_status": e.proof_status,
                    "metadata": e.metadata,
                    "proof": {
                        "kind": e.proof.kind,
                        "source": e.proof.source,
                        "url": e.proof.url,
                        "method": e.proof.method,
                        "status_code": e.proof.status_code,
                        "payload": e.proof.payload,
                        "metadata": e.proof.metadata,
                    }
                    if e.proof is not None
                    else None,
                }
                for e in evidence
            ]
            self.results.setdefault("evidence", []).extend(entries)
        return result

    async def _scope_and_preflight(self) -> str:
        try:
            self.security_policy.validate_target(self.target)
            domain = enforce_scope(self.target)
            self.results["domain"] = domain
        except ScopeViolationError as e:
            self.console.print(f"[bold red]Scope violation:[/bold red] {e}")
            raise ScopeViolationError(str(e)) from e

        ok, msg = check_os_security_updates(skip=self.skip_os_check)
        if not ok:
            self.console.print(f"[bold red]CRITICAL:[/bold red] {OS_UPDATE_MESSAGE}")
            raise RuntimeError(OS_UPDATE_MESSAGE)
        self._record_phase(
            "preflight",
            {"os_check": msg},
            [
                EvidenceRecord(
                    phase="preflight",
                    kind="os_check",
                    url=self.target,
                    method="GET",
                    status_code=None,
                    payload=None,
                    proof_status="skipped"
                    if self.skip_os_check
                    else "verified"
                    if ok
                    else "blocked",
                    metadata={"message": msg},
                    proof=ProofArtifact(
                        kind="os_check",
                        source="local_runtime",
                        url=self.target,
                        method="GET",
                        status_code=None,
                        metadata={"message": msg},
                    ),
                )
            ],
            PhaseContract(
                name="preflight",
                required_payload_keys=("os_check",),
                required_evidence_kinds=("os_check",),
                required_proof_kinds=("os_check",),
            ),
        )
        return domain

    async def _run_external_intel(self, domain: str) -> dict:
        self.console.print(
            "[bold blue]>[/bold blue] [white]Extracting external intelligence...[/white]"
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
        self._record_phase(
            "external_intel",
            providers,
            [
                EvidenceRecord(
                    phase="external_intel",
                    kind="intel_provider",
                    url=domain,
                    method="GET",
                    status_code=None,
                    payload=None,
                    proof_status="provider_status",
                    metadata={"providers": providers},
                    proof=None,
                )
            ],
            PhaseContract(
                name="external_intel",
                required_payload_keys=("shodan", "chaos"),
                required_evidence_kinds=("intel_provider",),
                allow_empty_evidence=True,
            ),
        )
        self.results["intel"] = intel
        return intel

    async def _run_api_inventory(self, domain: str) -> list:
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
        self._record_phase(
            "api_inventory",
            {
                "imported_templates": len(templates),
                "read_templates_eligible": sum(t.method == "GET" for t in templates),
                "other_methods_retained_not_sent": sum(t.method != "GET" for t in templates),
            },
            [
                EvidenceRecord(
                    phase="api_inventory",
                    kind="api_template",
                    url=t.url,
                    method=t.method,
                    status_code=None,
                    payload=t.url,
                    proof_status="cataloged",
                    metadata={"method": t.method, "source": t.source, "has_body": bool(t.body)},
                    proof=None,
                )
                for t in templates[:25]
            ],
            PhaseContract(
                name="api_inventory",
                required_payload_keys=("imported_templates",),
                allow_empty_evidence=True,
            ),
        )
        return templates

    async def _run_browser_discovery(self, domain: str) -> dict:
        browser_result = await discover_browser(
            self.target if "://" in self.target else f"https://{domain}/",
            self.budget,
            max_depth=0 if self.depth == "quick" else 1 if self.depth == "standard" else 2,
            max_pages=5 if self.depth == "quick" else 10 if self.depth == "standard" else 20,
            auth_headers=self.auth_headers,
        )
        browser_payload = {
            key: value
            for key, value in browser_result.items()
            if key not in {"urls", "form_templates"}
        }
        browser_payload["urls_discovered"] = len(browser_result.get("urls", []))
        self._record_phase(
            "browser_discovery",
            browser_payload,
            [
                EvidenceRecord(
                    phase="browser_discovery",
                    kind="page",
                    url=url,
                    method="GET",
                    status_code=None,
                    payload=None,
                    proof_status="inventory_candidate",
                    metadata={"source": "browser"},
                    proof=None,
                )
                for url in browser_result.get("urls", [])[:10]
            ],
            PhaseContract(
                name="browser_discovery",
                required_payload_keys=("urls_discovered",),
                allow_empty_evidence=True,
            ),
        )
        return browser_result

    async def _run_armada(
        self,
        domain: str,
        intel: dict,
        templates: list,
        browser_result: dict,
        shared: dict | None = None,
    ):
        self.console.print(
            "[bold blue]>[/bold blue] [white]Deploying agent swarm (The Armada)...[/white]"
        )
        if shared is None:
            shared = {
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
                "fuzz_payloads": self.fuzz_payloads,
                "max_payload_variants": self.max_payload_variants,
                "fuzz_cooldown_seconds": self.fuzz_cooldown_seconds,
                "fuzz_memory": AuraMemoryManager.get_instance() if self.fuzz_payloads else None,
            }
        armada = ArmadaOrchestrator(workers=self.workers)
        for name, handler in build_scan_handlers(shared).items():
            armada.register_handler(name, handler)

        graph = armada.plan_mission(domain, self.depth)
        armada_results = await armada.execute(graph, shared)
        raw_findings = list(armada_results.get("findings", [])) or shared.get("raw_findings", [])
        armada_phase = {
            "tasks": len(graph.tasks),
            "task_results": len(armada_results.get("tasks", {})),
            "specialists": [s.name for s in armada.hire_specialists(graph)],
        }
        self._record_phase(
            "armada",
            armada_phase,
            [
                EvidenceRecord(
                    phase="armada",
                    kind="agent_task",
                    url=shared["target_url"],
                    method="GET",
                    status_code=None,
                    payload=str(len(graph.tasks)),
                    proof_status="executed",
                    metadata={
                        "task_count": len(graph.tasks),
                        "specialists": armada_phase["specialists"],
                    },
                    proof=ProofArtifact(
                        kind="agent_task",
                        source="armada",
                        url=shared["target_url"],
                        method="GET",
                        status_code=None,
                        payload=str(len(graph.tasks)),
                        metadata={"task_count": len(graph.tasks)},
                    ),
                )
            ],
            PhaseContract(
                name="armada",
                required_payload_keys=("tasks", "task_results", "specialists"),
                required_evidence_kinds=("agent_task",),
                required_proof_kinds=("agent_task",),
            ),
        )
        self.results["phases"]["armada_failures"] = armada_results.get("failures", [])
        return armada_results, raw_findings

    async def _run_arsenal(
        self,
        domain: str,
        armada_results: dict,
        raw_findings: list,
        shared: dict | None = None,
    ):
        if self.arsenal_secondary and not armada_results.get("failures"):
            self.console.print(
                "[bold blue]>[/bold blue] [white]Engaging secondary heuristic probes (The Arsenal)...[/white]"
            )
            scanner = ArsenalScanner(
                verify_ssl=os.environ.get("SECAGENT_VERIFY_SSL", "true").lower() != "false",
                budget=self.budget,
                auth_headers=self.auth_headers,
            )
            endpoints = (
                (shared or {}).get("endpoints")
                if isinstance(shared, dict)
                else armada_results.get("shared", {}).get("endpoints")
                if isinstance(armada_results.get("shared"), dict)
                else None
            )
            if endpoints is None:
                endpoints = [f"https://{domain}"]
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
        return raw_findings

    async def run(self) -> dict:
        self._progress("PREFLIGHT", "start")
        domain = await self._scope_and_preflight()
        self._progress("PREFLIGHT", "done")

        from secagents.core.skill_manager import skill_manager

        if skill_manager.skills:
            self.console.print(
                "[bold green]+[/bold green] [white]Advanced Hunting Skills loaded from SKILL.md[/white]"
            )

        if self.setup_local_llm:
            hw = detect_hardware()
            self.console.print(f"  [cyan]Hardware:[/cyan] {hw.summary()}")
            _, ollama_msg = setup_ollama(pull=True)
            self.console.print(f"  [cyan]whichllm:[/cyan] {ollama_msg}")

        self._record_phase(
            "runtime",
            {"status": "host_execution"},
            [
                EvidenceRecord(
                    phase="runtime",
                    kind="runtime_context",
                    url=self.target,
                    method="GET",
                    status_code=None,
                    payload="host_execution",
                    proof_status="verified",
                    metadata={"execution": "local_host"},
                    proof=ProofArtifact(
                        kind="runtime_context",
                        source="host_runtime",
                        url=self.target,
                        method="GET",
                        status_code=None,
                        payload="host_execution",
                        metadata={"execution": "local_host"},
                    ),
                )
            ],
            PhaseContract(
                name="runtime",
                required_payload_keys=("status",),
                required_evidence_kinds=("runtime_context",),
                required_proof_kinds=("runtime_context",),
            ),
        )

        self._progress("INTEL", "start")
        intel = await self._run_external_intel(domain)
        self._progress("INTEL", "done")
        self._progress("INVENTORY", "start")
        templates = await self._run_api_inventory(domain)
        self._progress("INVENTORY", "done")
        self._progress("BROWSER", "start")
        browser_result = await self._run_browser_discovery(domain)
        self._progress("BROWSER", "done")

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
            "fuzz_payloads": self.fuzz_payloads,
            "max_payload_variants": self.max_payload_variants,
            "fuzz_cooldown_seconds": self.fuzz_cooldown_seconds,
            "fuzz_memory": AuraMemoryManager.get_instance() if self.fuzz_payloads else None,
        }
        self._progress("SCAN", "start")
        armada_results, raw_findings = await self._run_armada(
            domain, intel, templates, browser_result, shared
        )
        raw_findings = await self._run_arsenal(domain, armada_results, raw_findings, shared)
        self._progress("SCAN", "done")

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
            "[bold blue]>[/bold blue] [white]Validating signals and correlating chains (The Crucible)...[/white]"
        )
        self._progress("PROOF", "start")
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
                    outcomes.append(
                        await observe_state_contract(
                            state_contract, self.budget, policy=self.security_policy
                        )
                    )
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
                        await prove_ssrf(
                            ssrf_contract,
                            self.budget,
                            auth_headers=self.auth_headers,
                            policy=self.security_policy,
                        )
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
            if self.fuzz_payloads and shared["fuzz_memory"] is not None:
                for outcome in outcomes:
                    payload_spec = outcome.get("payload_spec") or {}
                    fingerprint = payload_spec.get("mutation_fingerprint")
                    mutation_name = payload_spec.get("mutation_name")
                    url = outcome.get("url")
                    check_key = outcome.get("check_key")
                    status = outcome.get("validation_status")
                    if not all((fingerprint, mutation_name, url, check_key)) or status not in {
                        "validated",
                        "rejected",
                    }:
                        continue
                    target_key = hashlib.sha256(str(url).encode()).hexdigest()
                    shared["fuzz_memory"].record_fuzz_outcome(
                        target_key, check_key, fingerprint, status
                    )
                    shared["fuzz_memory"].record_fuzz_feedback(
                        target_key, check_key, mutation_name, status == "validated"
                    )
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
        self._progress("PROOF", "done")

        registry = RegressionRegistry(self.results_dir / "regression")
        for f in validated:
            registry.register(f)

        # 6b. Crystallize Cognitive Memory Signals
        from secagents.core.aura_memory import TargetDNA

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
            "[bold blue]>[/bold blue] [white]Generating breach reports and auto-patches...[/white]"
        )
        self._progress("REPORT", "start")
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
                "payload_fuzzing": {
                    "enabled": self.fuzz_payloads,
                    "variants_generated": sum(
                        v.get("fuzz_variants_generated", 0)
                        for v in armada_results.get("tasks", {}).values()
                        if isinstance(v, dict)
                    ),
                    "variants_sent": sum(
                        v.get("fuzz_variants_sent", 0)
                        for v in armada_results.get("tasks", {}).values()
                        if isinstance(v, dict)
                    ),
                    "repeats_skipped": sum(
                        v.get("fuzz_variants_repeated", 0)
                        for v in armada_results.get("tasks", {}).values()
                        if isinstance(v, dict)
                    ),
                    "variants_validated": sum(
                        bool(item.get("validated"))
                        for item in outcomes
                        if (item.get("payload_spec") or {}).get("mutation_fingerprint")
                    ),
                },
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
            "[bold blue]>[/bold blue] [white]Archiving mission data to persistent memory...[/white]"
        )
        hermes = HermesMemory(self.results_dir / "hermes" / "memory.db")
        retro = RetrospectiveAgent(hermes)
        self.results["hermes"] = retro.analyze(self.results)
        hermes.export_json(self.results_dir / "hermes" / "export.json")

        self._progress("REPORT", "done")

        return self.results
