# Reconnaissance

Build a bounded, attributed inventory of authorized assets and application routes. Discovery is an observation, not vulnerability proof.

1. Start from the operator's exact scope and record the source of every hostname, URL and API template.
2. Combine passive DNS, HTTP links, JavaScript routes, browser network traffic and OpenAPI/HAR imports. Check scope before each live request.
3. Preserve method, path, query, content type, body shape and authentication context. Mark write templates as inventory only until a state contract exists.
4. Deduplicate normalized routes while retaining distinct methods and authorization contexts.
5. Rank routes by trust boundary, sensitive data, role, and change risk. Prefer a narrow deep dive when the inventory reveals a valuable workflow.
6. Stop at the shared request cap, per-host rate limit, crawl depth or deadline. Report the termination reason and inventory coverage.

Output an asset inventory with provenance and a short list of hypotheses requiring separate proof.
