# QuietWard Response protocols

QuietWard Response keeps observation and response messages in separate versioned contracts.

- `quietward-event-schema-v1.json` — sensor observations and evidence
- `quietward-action-schema-v1.json` — policy-approved typed ActionRequest and authenticated ActionResult messages

Neither repository imports the other. Compatibility is defined by these serialized contracts.

## Event protocol v1

Version `1.0` is the first stable event envelope between sensors and QuietWard Response.

Compatibility contract:

- Producers must send a supported `schema_version`; unsupported major versions fail closed.
- Fields required by v1 remain required for the lifetime of the v1 major version.
- New optional nested evidence fields may be added without changing the major version; the top-level envelope remains strict.
- Breaking changes require a new schema file and major version, with an explicit migration and overlap period.
- `event_id` is a UUID and is globally idempotent. Replays of an accepted ID return `409 Conflict`.
- QuietWard treats that duplicate-ID response as successful retry completion because a network timeout may occur after Response has already committed the event.
- Timestamps are timezone-aware RFC 3339 values and are normalized to UTC.
- QuietWard local event identifiers do not need to be UUIDs. The integration adapter deterministically maps them to v1 UUIDs and preserves the original identifier in metadata.

When `source` is `quietward`, v1 requires authenticated delivery by default. Authentication is outside the JSON body so the observation schema stays sensor-neutral.

## Agent request authentication

QuietWard requests use HMAC-SHA256 with these headers:

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

The action protocol is deliberately narrower than the event protocol. It carries typed capabilities, never command strings.

The server-side analyst lifecycle may be `pending` or `approved`, but those states are **not** delivered to the endpoint as ActionRequest messages. An endpoint receives only a policy-allowed action after Response has transitioned it to `dispatching`, or an `executing` action returned strictly for reconciliation/recovery. Accordingly, the v1 ActionRequest schema requires `policy_allowed: true` and permits only `dispatching` or `executing`.

`ActionRequest` identifies:

- action ID and incident ID
- exact target agent and host
- registered action type
- validated typed parameters
- requester and approval ID
- request and expiry timestamps
- dispatch/recovery lifecycle state
- deterministic policy decision and reasons

`ActionResult` identifies:

- exact action, agent, and host
- executing/succeeded/failed status
- start/completion timestamps
- structured result, error, and evidence
- agent version

### v1 allowlist

The only executable action is:

```text
restart_quietward_demo_service
```

Its parameter object must be empty. Despite the name, it does not operate a real OS service. The QuietWard executor modifies only its dedicated `quietward-response-demo.json` state fixture.

There is no protocol form for:

- shell commands
- PowerShell/cmd/bash commands
- arbitrary executable paths
- arbitrary service names
- arbitrary process IDs
- file deletion/quarantine
- firewall rules
- host isolation

Unknown action types, non-empty parameters, unexpected fields, unapproved policy state, wrong target identity, or expired new dispatches fail closed on the endpoint.

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

An `executing` action may be returned again to the same authenticated endpoint after a restart so the endpoint can reconcile an interrupted delivery. QuietWard persists execution intent before changing local state, keeps a durable terminal-result ledger, and marks the dedicated demo fixture with the action ID and prior result. Those local records close the important crash windows: a repeated action ID returns the previously applied result instead of changing the fixture twice. Response also rejects a duplicate terminal result when its stored result/evidence does not match.

If an agent is disabled after execution acknowledgement, it receives no new work. Its authenticated poll may return only its own already-`executing` action for reconciliation, and result submission remains limited to matching `executing`/terminal lifecycles. Cancelled or pre-execution actions cannot be revived by the disabled credential.

Authenticated result submissions that fail post-authentication lifecycle/ownership validation are recorded as rejected action-result audit events without logging credential material.
