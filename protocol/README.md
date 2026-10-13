# QuietWard Response protocols

QuietWard Response keeps observation and response messages in separate versioned contracts.

- `quietward-event-schema-v1.json` — sensor observations and evidence
- `quietward-action-schema-v1.json` — policy-approved typed ActionRequest and authenticated ActionResult messages

Neither repository imports the other. Compatibility is defined by these serialized contracts.

## Event protocol v1

Version `1.0` is the stable event envelope between sensors and QuietWard Response.

Compatibility contract:

- Producers must send a supported `schema_version`; unsupported major versions fail closed.
- Fields required by v1 remain required for the lifetime of the v1 major version.
- New optional nested evidence fields may be added without changing the major version; the top-level envelope remains strict.
- Breaking changes require a new schema file and major version, with an explicit migration and overlap period.
- `event_id` is a UUID and is globally idempotent. Replays of an accepted ID return `409 Conflict`.
- QuietWard treats that duplicate-ID response as successful retry completion because a network timeout may occur after Response has already committed the event.
- Timestamps are timezone-aware RFC 3339 values and are normalized to UTC.

QuietWard response-context v1.1 remains an observation-only extension carried inside the v1 event envelope. It may include coarse priority, evidence strength, investigation hints, a recommended playbook, and an opaque `resolution_target_handle`. That handle is not a path, PID, account, address, or command and grants no executable authority.

When `source` is `quietward`, v1 requires authenticated delivery by default. Authentication is outside the JSON body so the observation schema stays sensor-neutral.

## Agent request authentication

QuietWard/Response agent requests use HMAC-SHA256 with these headers:

```text
X-QWR-Agent-ID
X-QWR-Key-ID
X-QWR-Timestamp
X-QWR-Nonce
X-QWR-Signature
```

The canonical signed message is:

```text
HTTP_METHOD
PATH_AND_QUERY
UNIX_TIMESTAMP
NONCE
SHA256(EXACT_BODY_BYTES)
```

The server checks the enrolled agent/key ID, body signature, timestamp skew, nonce uniqueness, enabled state, and host binding. Used nonces are persisted for replay resistance. Valid nonces remain consumed even if later business validation rejects the request.

HMAC is not a replacement for TLS. Non-loopback deployment must protect credentials and transport confidentiality.

## Action protocol v1

The action protocol carries typed capabilities, never command strings. An action is valid only when it is present in the server registry, declared by the signed endpoint capability report, enabled for the incident, policy-allowed, and bound to an analyst approval.

The server-side analyst lifecycle may be `pending` or `approved`, but those states are **not** delivered to the endpoint as ActionRequest messages. An endpoint receives only a policy-allowed action after Response has transitioned it to `dispatching`, or an `executing` action returned strictly for reconciliation/recovery. Accordingly, the v1 ActionRequest schema requires `policy_allowed: true` and permits only `dispatching` or `executing`.

`ActionRequest` identifies the exact incident, host, agent, action type, validated typed parameters, approval binding, expiry, and policy result. `ActionResult` records the matching action/agent/host, lifecycle status, structured result, error/evidence, and agent version.

## vNext controlled action surface

### Read-only diagnostics

```text
collect_host_diagnostic
collect_process_diagnostic
collect_network_diagnostic
collect_incident_triage_bundle
```

These actions are parameterless. The triage bundle composes bounded diagnostics and creates endpoint-local opaque process evidence handles. It does not return process command lines, executable paths, or raw remote network addresses.

### Dedicated demo mutation

```text
restart_quietward_demo_service
```

This modifies only the dedicated QuietWard Response demo fixture and does not operate a real OS service.

### Evidence-bound process containment

```text
terminate_evidence_process
```

This is a real high-impact endpoint action and therefore has additional controls:

- explicit analyst approval is required
- the only parameter is `evidence_handle`
- the handle must match `qwrp-[0-9a-f]{32}`
- arbitrary PID input is not accepted
- the handle must occur in a **successful triage bundle for the same incident, host, and agent** before server policy will dispatch it
- the endpoint resolves the handle from its private evidence store
- the endpoint revalidates process image, parent identity, and process-start marker immediately before termination
- critical/system processes and the Response agent's own process lineage are protected
- stale, missing, changed, cross-incident, or expired evidence fails closed
- there is no arbitrary shell or command execution path

Process termination is intentionally irreversible. It is not considered release-complete until local and joint qualification gates pass.

## Explicitly absent surfaces

There is no protocol form for:

- shell, PowerShell, cmd, or bash commands
- arbitrary executable paths
- arbitrary process IDs
- arbitrary service names
- arbitrary file deletion/quarantine paths
- arbitrary firewall/network targets
- unbounded host isolation

Later remediation capabilities must follow the same evidence-bound pattern rather than introducing free-form target fields.

## Action lifecycle

```text
pending
  ↓ single-shot analyst approval
approved
  ↓ policy recheck + agent poll
dispatching
  ↓ endpoint acknowledgement
executing
  ↓ typed ActionResult
succeeded | failed
```

Other terminal paths are `rejected`, `expired`, and `cancelled`.

Approval/rejection is single-shot at the analyst API boundary. Cancellation and revocation use separate lifecycle transitions rather than rewriting the original approval record.

A `dispatching` action can still be cancelled if its incident closes or its target agent is disabled before the endpoint acknowledges `executing`. Once `executing` is stored, the lifecycle remains available for tightly bound recovery/result reconciliation.

An `executing` action may be returned again to the same authenticated endpoint after a restart so the endpoint can reconcile an interrupted delivery. The endpoint persists execution intent before changing local state and keeps a durable terminal-result ledger. A repeated action ID replays the stored terminal result instead of intentionally executing the action a second time.

If an agent is disabled after execution acknowledgement, it receives no new work. Its authenticated poll may return only its own already-`executing` action for reconciliation, and result submission remains limited to matching executing/terminal lifecycles. Cancelled or pre-execution actions cannot be revived by the disabled credential.

Authenticated result submissions that fail post-authentication lifecycle/ownership validation are recorded as rejected action-result audit events without logging credential material.

## Combined vNext release condition

The combined QuietWard + QuietWard Response update is additionally gated by `scripts/verify_vnext_resolution_coverage.py`. The release remains blocked while any QuietWard finding category lacks a tested Response resolution path. A category may be satisfied by a safely automated evidence-bound action or, where universal automated mutation would be unsafe, a tested guided escalation/recovery workflow with explicit closure criteria.
