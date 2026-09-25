# SecAgent build-order implementation status

Updated 25 September 2026. This file tracks changes made after the point-in-time [AKCA comparison](SECAGENT_VS_AKCA_REVIEW.md). The comparison describes the repository before this implementation pass.

## Implemented in this pass

1. **Default scan correctness:** route recon and universal scanning to their intended handlers; report task failures and skipped external tools; remove fabricated MCP scan/proof outcomes.
2. **Evidence quality:** carry typed check, method, headers, body and payload through candidate generation; replay supported checks with an unmodified control; classify unsupported, browser-only, identity-dependent and POST proof as manual leads. Keep inconclusive and rejected outcomes distinct from validated findings.
3. **Request safety:** enforce scope on scanner seeds, browser requests and Go crawler redirects; stop automatic redirect following; verify TLS by default; use argument arrays for external binaries; skip state-changing POST checks by default; remove localhost SSRF probes from unattended Arsenal scanning.
4. **Reporting and CI:** version the JSON report, include proof and incomplete coverage, redact common credential fields in exports, fix the Go test command and localhost scope fixture, and align README claims with actual sandbox and proof behavior.

## Next build-order work before a production-readiness claim

### Implemented in the second pass

1. **Built-in HTTP execution budget:** one counter, per-host rate limiter, concurrency cap and deadline now cover the default browser discovery, CVE checks, Arsenal probes and Crucible proof replay. Proof capsules have a separate bounded replay budget. JSON, Markdown, HTML and CLI results show consumption and termination. External binaries and provider intelligence are skipped in this bounded path because their internal requests cannot yet be metered or scope-checked centrally.
2. **Proof policy catalog and fixtures:** every registered built-in check has an explicit policy. Supported active checks need a negative control and three positive observations; response status and body hashes are retained. XSS, IDOR, stateful and callback checks require capabilities the default scan cannot provide and stay manual or skipped. The unsafe metadata SSRF, default Log4Shell and RFI callbacks were removed. Artifact exposure checks now request their actual paths; the dead host-header check was removed.
3. **Read-only authenticated inventory:** CLI sessions are loaded from named environment variables. OpenAPI/Swagger and HAR import retain method and body in memory; only GET templates enter the default active scan. Unproven standalone API heuristics and write requests are disabled and recorded as coverage gaps.
4. **Browser inventory:** the default scan attempts a bounded Playwright crawl. Every browser request is checked for scope, method and budget; links, network URLs and form templates feed the inventory. Missing browser support and blocked requests are reported.
5. **Runtime claim:** Fortress was removed from the Python scan path. Reports state `host_execution`; operators who need isolation must run SecAgent inside their own container or virtual machine.
6. **Quality gates:** added hermetic budget, proof, callback, artifact-path and API import fixtures; added CTest for the C++ matcher and CI execution of it; Python unit tests, Go tests and full Python mypy pass locally. Rust and C++ tools are unavailable on this host, so those native gates remain CI-only here.

### Implemented in the third pass

1. Configured Shodan and Chaos calls now consume the shared request budget through exact HTTPS provider destinations. Unmetered external binaries remain disabled.
2. XSS candidates now require real Chromium execution with a clean negative control and an independent positive replay. A real local browser fixture passes both vulnerable and escaped cases. An old unscoped BrowserCluster helper was retired.
3. Opt-in identity contracts use two distinct session headers, an anonymous control and two independent GET replays. Opt-in state contracts require a baseline read, negative control, probe read and cleanup after each write; observed state changes remain manual leads. Opt-in SSRF contracts require an approved provider and callback domain, a clean unsent registration, and two scan-bound callback observations. These paths are documented in [PROOF_CONTRACTS.md](PROOF_CONTRACTS.md).
4. The default scan now retains a target URL's scheme and port. Query probes replace an existing parameter rather than appending a duplicate. Artifact findings use the actual artifact URL and deduplicate by it.
5. A controlled localhost positive/negative comparison with AKCA was run and recorded in [QUALITY_BENCHMARK.md](QUALITY_BENCHMARK.md). SecAgents found three intended positives and no safe-fixture findings. AKCA's selected profile reported incomplete XSS coverage, so these runs cannot establish comparative accuracy. The harness and raw local reports are retained for replay.

### Still required before a production-readiness claim

1. Execute optional external binaries behind a proven scoped egress boundary that meters every target request; only then re-enable them. A configured provider endpoint is metered, but an arbitrary subprocess cannot satisfy the same contract yet.
2. Verify the OAST protocol against a live operator-controlled service, including event integrity and callback retention. Confirm state cleanup under failures and cancellations on a disposable target; the current cleanup is best effort. Expand separate-identity fixtures to realistic authorization models.
3. Expand the web/API corpus to independent applications and vulnerability classes. Repeat scans with equivalent module coverage and complete runs before publishing comparative precision, recall or performance claims.
4. Run the configured Rust and C++ CI jobs on this change set and inspect their results. Their toolchains and a running Docker daemon were unavailable locally, and these uncommitted changes have not been pushed to CI.

The current default scan is suitable for further controlled development and authorized testing. It is **not yet a complete or industry-ready replacement for AKCA**.
