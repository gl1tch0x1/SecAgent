# Evidence Validation

A candidate is a lead until its proof policy is satisfied. The LLM may summarize evidence but cannot manufacture network observations, browser execution, identity separation or state changes.

1. Preserve the exact target URL, method, normalized request template, response status, relevant headers, and a redacted body digest.
2. Establish a baseline and a negative control with the same authorization context. Repeat positive observations independently within the shared budget.
3. For XSS, require actual browser execution in a controlled fixture. Reflection alone is insufficient.
4. For authorization, compare separate identities and verify ownership of the returned object or effect.
5. For blind SSRF or RCE, require an operator-controlled callback tied to the scan. Never substitute cloud metadata or third-party callback hosts.
6. For write methods, capture pre-state, intended change, post-state and cleanup result.

Classify each candidate as `verified`, `rejected`, or `manual_lead`; give the missing evidence and termination reason. Never infer HTTP `200` or a successful exploit from a catalog entry or a model assertion.
