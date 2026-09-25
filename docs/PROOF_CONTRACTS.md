# Opt-in proof contracts

The default scan remains read-only. These contracts enable specific, authorized proof cases without adding credentials to files or reports. Set `ALLOWED_DOMAINS` to include every target host. Supply each header as `Name: value` in the named environment variable. Contract files must not contain secrets.

## Two-identity resource proof

Use `secagent scan --target https://app.example --identity-contract identity.json` with:

```json
[
  {
    "owner_url": "https://app.example/api/accounts/owner",
    "other_control_url": "https://app.example/api/accounts/other",
    "private_marker": "owner-private-marker",
    "owner_header_env": "SECAGENT_OWNER_HEADER",
    "other_header_env": "SECAGENT_OTHER_HEADER"
  }
]
```

The marker must identify private owner data and must not appear in the other account or anonymous response. SecAgents makes two independent GET runs under the owner, other, and anonymous identities. It publishes an IDOR finding only if the other identity sees the private marker twice while controls remain clean. Report evidence contains hashes and booleans, never header values or the marker.

## Stateful API observation

Use `--state-contract state.json` with:

```json
[
  {
    "read_url": "https://app.example/api/items/fixture",
    "write_url": "https://app.example/api/items/fixture",
    "write_method": "PATCH",
    "control_body": "{\"value\":\"baseline-value\"}",
    "probe_body": "{\"value\":\"probe-value\"}",
    "cleanup_url": "https://app.example/api/items/fixture",
    "cleanup_method": "PATCH",
    "cleanup_body": "{\"value\":\"baseline-value\"}",
    "baseline_marker": "baseline-value",
    "probe_marker": "probe-value",
    "header_env": "SECAGENT_STATE_HEADER"
  }
]
```

Choose a disposable fixture record and a cleanup operation that restores it. Before any write, the runner requires at least 13 unused request slots and 90 seconds. It reads baseline state, sends a negative control, performs two independent probe writes, and attempts cleanup after every write. The output is a manual lead even when the state change reproduces: the observed transition alone does not establish a vulnerability class. A failed cleanup is reported as incomplete and may require operator repair. Imported OpenAPI/HAR writes remain unsent without a contract.

## Out-of-band SSRF proof

Use `--ssrf-contract ssrf.json` with:

```json
[
  {
    "probe_url": "https://app.example/api/fetch?url=about:blank",
    "parameter": "url",
    "provider_url": "https://oast-provider.example",
    "provider_token_env": "SECAGENT_OAST_TOKEN"
  }
]
```

Set `OAST_PROVIDER_DOMAINS` to the exact HTTPS provider hostname and `OAST_CALLBACK_DOMAINS` to the exact callback hostname. The provider must support `POST /registrations` with a JSON `nonce`, returning `registration_id` and `callback_url`; and `GET /registrations/{id}/events`, returning `events` with matching `registration_id` and `nonce`. Both endpoints use `Authorization: Bearer <token>`. SecAgents registers one unsent negative control and two independent callback URLs, sends only the two scoped GET probes, and publishes SSRF only when both matching callback events arrive and the control stays empty. Callback URLs and tokens are omitted from reports. No provider or callback destination is configured by default.

Provider integration has been verified against a controlled mock service, not a live external provider. Test your provider's registration, event integrity, timing and retention before relying on OAST findings.
