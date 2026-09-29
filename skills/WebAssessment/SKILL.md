# Web Assessment

Understand the application workflow and trust boundaries before selecting a check. Use bounded, context-aware probes against approved routes.

1. Identify input context: HTML text, attribute, script, URL, template, file path or server-side parser. Choose one controlled candidate and a harmless negative control.
2. Establish baseline response status, headers and body digest. Compare a minimal variation within the shared budget.
3. For XSS, require browser execution in an authorized fixture; reflection is only a lead.
4. For blind SSRF or command behavior, require an operator-owned callback bound to this scan. Never use metadata or third-party callback destinations.
5. For file access, compare requested artifact paths with an unrelated path and verify the returned content matches the claimed artifact.
6. For state-changing workflows, require pre-state read, negative control and cleanup. Stop if the expected state cannot be restored.

Output a proof plan and measured observations. Label any unverified behavior as `manual_lead`.
