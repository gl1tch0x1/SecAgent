# Hunt Planning

Use this skill to turn an authorized target and a bounded inventory into testable hypotheses. It produces a plan, never a claim that a vulnerability exists.

1. State the approved domains, identities, methods, request cap, rate limit, and deadline. Mark missing inputs as coverage gaps.
2. Map entry points by trust boundary: anonymous to authenticated, user to admin, browser to API, API to downstream service, and application to cloud resources.
3. Rank hypotheses by impact, likelihood, evidence availability, and traffic cost. Prefer a small number of high-value tests over broad payload spraying.
4. For each hypothesis, specify the baseline, one controlled variation, a negative control, the expected observation, and the stop condition.
5. Require separate identities for authorization claims, browser execution for XSS, an operator-controlled callback for blind behavior, and a state read plus cleanup contract for write methods.
6. Record unexplored paths and capability gaps as leads. Do not promote a plan or heuristic to a confirmed finding.

Output a compact JSON plan with `scope`, `assumptions`, `hypotheses`, `required_capabilities`, `budget`, and `coverage_gaps`. Each hypothesis should include its proof policy and expected evidence.
