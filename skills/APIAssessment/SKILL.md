# API Assessment

Use OpenAPI definitions and captured requests as method-preserving inventory. Keep path, query, body shape, content type, and authentication context together.

## Hunting workflow

1. Identify resources and object identifiers, then map which roles can read and change each resource.
2. Compare an authorized request with a separate identity and a deliberately unauthorized object. Do not call a `200` response an authorization bypass without checking the returned object's ownership and state.
3. Trace alternate representations and API versions for the same resource. Compare server-side authorization, not merely client-side UI controls.
4. Inspect pagination, filtering, export and batch endpoints for inconsistent object checks using bounded requests.
5. Treat GraphQL fields and mutations as distinct operations. Preserve operation names, variables and query depth in the inventory.
6. Probe POST, PUT, PATCH and DELETE only when the operator supplies a state read, negative control and cleanup procedure. Stop on unexpected state changes.

Return exact request and response metadata with secrets redacted. Mark missing identities, state contracts, or replay evidence as coverage gaps.
