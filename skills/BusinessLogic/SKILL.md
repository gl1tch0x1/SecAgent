# Business Logic

Model the application as states, transitions, actors and invariants before testing. High-value workflows include account recovery, invitations, approvals, checkout, credits and ownership transfer.

1. Write the invariant in plain language, such as "a user may redeem this benefit once" or "only an owner may approve this transfer".
2. Identify the smallest sequence of authorized actions that reaches the decision point. Capture the state before each action.
3. Compare roles, workflow order, duplicate submission and stale state using controlled fixtures. Keep concurrency low and bound retries.
4. For race hypotheses, require an operator-owned test object, a known safe outcome and a cleanup path. Do not run concurrent writes on production records without that contract.
5. Measure the final server-side state, not merely an HTTP status or UI message. Repeat the observation independently and include a negative control.

Report an observed invariant violation with state evidence. If state cannot be read safely, retain the idea as an unverified lead.
