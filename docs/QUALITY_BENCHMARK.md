# Controlled local fixture comparison

Recorded 25 September 2026. The harness is [quality_compare.py](../benchmarks/quality_compare.py). It starts the same localhost application in vulnerable and safe modes, runs each scanner under a 3,000-request and 300-second configured cap, and records wall time and the fixture's actual HTTP request count. The vulnerable mode contains a simple error-based SQL injection, reflected script execution and exposed `/.git/config`. The safe mode removes those three conditions. Both modes set the tested security headers. No external target was scanned.

SecAgents confirmed the three intended positive cases and published zero findings on the safe mode. The positive run took 13.05 seconds and the fixture observed 112 requests. The safe run took 11.97 seconds and the fixture observed 105 requests. The SecAgents reports recorded the same request counts and no budget termination. This is 3/3 detection of the intended positives and zero published findings on the safe fixture **in this tiny, purpose-built corpus only**. The safe XSS reflection candidate was rejected after browser execution did not reproduce the canary dialog.

AKCA v0.2.0 (engine module installed through `go install`, root module v0.2.2) was run with `-m sql,xss --no-fuzzing --no-oast`, a 50-request crawler cap, 10-page/endpoint caps, the same total request and time caps, and JSON output. Both runs reported zero findings. Each took about 244 seconds and the fixture observed 877 HTTP requests; AKCA's report counted 2,385 internal requests/budget units. Its log marked the XSS module incomplete due to module budget allocation in both runs, even though the total cap was not exhausted. The SQL module completed without a reported finding. A narrower SQL-only attempt without a module quota hit its 120-second deadline and also produced no finding. An earlier SQL/XSS/fuzz run exhausted an 800-unit cap before proof modules completed.

These observations do **not** establish a general accuracy or performance ranking. The fixture is small and deliberately matches SecAgents' current signatures; SecAgents ran its default built-in checks while AKCA ran selected modules; AKCA reported incomplete XSS coverage; and the scanners count internal work differently. A production comparison needs independent, diverse applications, equivalent enabled checks, verified completion for both scanners, and repeated measurements. The current numbers establish only what happened in these local runs.

Raw local outputs are under `benchmark-results/` (ignored by Git to avoid committing scan artifacts). Re-run with:

```powershell
venv\Scripts\python.exe benchmarks\quality_compare.py --akca-binary "$env:TEMP\secagent-akca-bin\akca.exe" --request-budget 3000 --time-budget-seconds 300 --timeout 330
```

The harness removes Slack, Jira, Shodan and Chaos environment variables before launching scans. It retains the raw scanner reports and logs, plus fixture request counts, for manual taxonomy and evidence review.
