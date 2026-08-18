# QuietWard Response protocols

QuietWard Response keeps observation and response messages in separate versioned contracts.

- `quietward-event-schema-v1.json` — sensor observations and evidence
- `quietward-action-schema-v1.json` — approved typed ActionRequest and authenticated ActionResult messages

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

The server checks the enrolled agent/key ID, body signature, timestamp skew, nonce uniqueness, enabled state, and host binding. Used nonces are persisted for replay resistance.

HMAC is not a replacement for TLS. Non-loopback deployment must protect credentials and transport confidentiality.

## Action protocol v1

The action protocol is deliberately narrower than the event protocol. It carries typed capabilities, never command strings.

`ActionRequest` identifies:

- action ID and incident ID
- exact target agent and host
- registered action type
- validated typed parameters
- requester and approval ID
- request and expiry timestamps
- lifecycle state

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

Unknown action types or non-empty parameters fail closed both on the server and endpoint.

## Action lifecycle

```text
pending
  ↓ analyst approval
approved
  ↓ policy evaluation + agent poll
dispatching
  ↓ endpoint acknowledgement
executing
  ↓ typed ActionResult
succeeded | failed
```

Other terminal paths are `rejected`, `expired`, and `cancelled`.

An `executing` action may be returned again to the same authenticated endpoint after a restart so the endpoint can reconcile an interrupted delivery. QuietWard persists execution intent before changing local state, keeps a durable terminal-result ledger, and marks the dedicated demo fixture with the action ID and prior result. Those two local records close the important crash windows: a repeated action ID returns the previously applied result instead of changing the fixture twice. Response also rejects a duplicate terminal result when its stored result/evidence does not match.
