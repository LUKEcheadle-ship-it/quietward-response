# QuietWard Response

QuietWard Response is a standalone incident-investigation and controlled-response platform. It accepts validated security telemetry, correlates observations into incidents, produces deterministic response plans, manages analyst approval and policy, dispatches narrowly typed actions to a Response-owned agent, and maintains a tamper-evident audit trail.

It is a **separate product and repository from QuietWard**. Response does not require Response code inside QuietWard and does not modify the QuietWard repository.

> **Current release candidate:** `v1.2.0-alpha.1` (`1.2.0a1`) on `feature/response-v12-hardening`.
>
> v1.2 adds bounded host/process/file/network diagnostics, short-lived incident-bound opaque resource handles, opt-in exact-process termination, reversible managed-file quarantine/restore, signed endpoint capability negotiation, agent-key rotation, analyst bearer RBAC, API abuse bounds, sensitive-field redaction, and signed audit checkpoints. There is still **no generic remote command surface**.

## Response coverage

`GET /api/v1/incidents/{incident_id}/response-plan`

Plans cover malware/ransomware, execution/privilege, identity attacks, persistence, network/C2 activity, containers/Kubernetes, vulnerabilities/configuration, evidence/sensor integrity, and operational failures.

Every plan separates investigation, containment, recovery, escalation, and the exact executable action list. Planned/manual/blocked guidance is not executable code.

## v1.2 executable action surface

The registry is explicit and finite:

| Action | Type | Targeting |
|---|---|---|
| `restart_quietward_demo_service` | demo state change | no parameters |
| `collect_host_diagnostic` | read-only | no parameters |
| `collect_process_diagnostic` | read-only | bounded process snapshot; issues process handles |
| `collect_network_diagnostic` | read-only, Linux | bounded `/proc/net` snapshot; raw network addresses are not returned |
| `terminate_process_by_handle` | high-impact containment | short-lived opaque process handle only |
| `collect_file_diagnostic` | read-only | configured managed roots only; issues file handles |
| `quarantine_artifact_by_handle` | reversible containment | short-lived opaque managed-file handle only |
| `restore_quarantined_artifact_by_handle` | rollback | quarantine rollback handle only |

All eight actions require explicit analyst approval and deterministic server policy.

There is no shell, PowerShell, cmd, bash, generic script, raw PID, raw filesystem path, or raw network-target execution API.

## Opaque resource handles

A Response agent creates random `qwrh1_...` handles from its own local observation of a resource. The control plane cannot invent a PID, file path, or socket identity.

Handles are:

- local to the agent;
- incident/host/agent provenance-bound;
- short-lived;
- single-consumption for mutating operations;
- revalidated against current local identity before mutation.

Process termination and file quarantine are capped at 240-second action TTLs. Normal analyst UI does not expose free-form opaque-handle entry: it offers only unexpired handles returned by successful prior actions for the same incident and selected agent.

## Process containment boundary

Process diagnostics and exact-process termination are implemented on Linux and Windows without server-supplied commands.

The agent:

- returns a bounded process snapshot;
- protects its own process/parent and critical OS processes;
- binds handles to identity data beyond PID;
- revalidates identity immediately before termination;
- rejects stale/reused PID identities;
- uses pidfd-bound signaling on Linux where qualified;
- performs bounded exit verification;
- fails closed when an interrupted termination result is indeterminate.

High-impact process termination is disabled by default in local agent configuration.

## File containment boundary

File diagnostics/quarantine operate only inside explicitly configured Response-agent managed roots.

The agent:

- enumerates bounded regular files;
- excludes symbolic links;
- never accepts a server-supplied path;
- binds identity to filesystem metadata plus SHA-256 content;
- revalidates before quarantine and verifies after the move;
- writes into a private quarantine directory outside all managed roots;
- creates a separate rollback handle;
- refuses restore when the original path is occupied, outside the managed root, or the quarantine object changed;
- records consumption receipts so exact replay cannot apply a mutation twice.

The remaining documented file limitation is the narrow same-user filesystem race between final identity verification and a portable cross-platform move. Platform-specific descriptor/handle-relative hardening remains future work.

## Network diagnostic boundary

`collect_network_diagnostic` is currently **Linux-only and read-only**.

It reads bounded `/proc/net/{tcp,tcp6,udp,udp6}` state directly without invoking a shell or subprocess and returns at most 256 rows containing:

- protocol and address family;
- local/remote scope;
- local/remote ports;
- connection state;
- a truncated SHA-256 identity for a concrete remote address when applicable;
- a short-lived local opaque socket handle.

Raw local/remote IP addresses, socket UID, and inode remain agent-local and are not returned to the control plane. Firewall changes and host isolation remain unavailable.

## Signed endpoint capabilities

Agents sign supported and locally enabled action sets to:

`POST /api/v1/agents/{agent_id}/capabilities`

The report attests `arbitrary_command_execution=false` and uses the `qwrh1` handle protocol.

Server policy refuses non-demo actions when:

- the agent never reported capabilities;
- the report is older than 15 minutes or implausibly future-dated;
- the exact action is not locally enabled;
- the agent is disabled or bound to another host.

The official enrollment path sends the first signed report. The official poll path refreshes it before every poll:

```text
python scripts/poll_response_agent.py --config PATH_TO_AGENT_JSON
```

The Agents page shows Fresh / Stale / Never reported capability state and the signed enabled action set.

## Agent credential rotation

Use:

```text
python scripts/rotate_response_agent_key.py --config PATH_TO_AGENT_JSON
```

Rotation is two-phase:

1. current credential prepares a five-minute pending credential;
2. helper stores it privately in a `.next` sidecar;
3. pending credential proves possession and activates itself;
4. old credential is immediately revoked for normal HMAC traffic;
5. new key proves normal traffic through capability sync;
6. `.next` atomically replaces the original local config.

Recover an interrupted staged rotation with:

```text
python scripts/rotate_response_agent_key.py --config PATH_TO_AGENT_JSON --recover-next
```

Retired HMAC key material is not persisted after activation. One-time secrets are excluded from normal listings/audit details and are not printed by the helper.

## Analyst authentication and RBAC

Loopback `development` retains the local `X-Actor-ID` convenience path.

Outside loopback development, Response will not start without `QWR_ANALYST_CREDENTIALS`.

Roles:

- `viewer` — read-only;
- `responder` — incident changes plus action create/approve/reject;
- `admin` — responder plus agent enable/disable and unclassified mutation endpoints.

Generate a high-entropy token/hash entry:

```text
python scripts/generate_analyst_token.py --actor-id alice --role admin
```

Configuration stores only the SHA-256 token hash. Browser bearer tokens are session-scoped; TLS and normal XSS/CSP hygiene remain required for remote deployment.

## Evidence and audit hardening

Sensitive credential-like fields are redacted before event/action/note persistence.

The database audit trail remains hash chained. v1.2 also supports externally retainable HMAC-signed checkpoints:

- `GET /api/v1/audit/checkpoint`
- `POST /api/v1/audit/checkpoint/verify`

A retained signed checkpoint can detect ordinary chain tamper, consistent full-history recomputation after the checkpoint, deletion/truncation of already-checkpointed history, and checkpoint signature tamper.

Production/non-loopback deployments must replace the development checkpoint secret using `QWR_AUDIT_CHECKPOINT_SECRET`. A trusted retained checkpoint can also be required at startup via `QWR_TRUSTED_AUDIT_CHECKPOINT_PATH`.

This is stronger tamper evidence, not a claim of immutable/WORM external storage.

## API abuse bounds

The qualified single-process/single-worker runtime enforces:

- request-size limit (`QWR_API_MAX_REQUEST_BYTES`, default 1 MiB);
- per-client `/api/v1` rate limit (`QWR_API_RATE_LIMIT_PER_MINUTE`, default 600/minute);
- fail-closed 413/429 responses;
- bounded ActionResult/evidence sizes;
- `no-store`, `nosniff`, frame, referrer and permissions-policy headers.

Multi-worker shared rate limiting remains outside the v1.2 qualified boundary.

## Integrity trust freeze

When an incident contains explicit sensor/evidence integrity compromise, medium/high/critical state-changing actions are blocked by deterministic policy until the trust issue is resolved. A compromised sensor cannot use its own tamper evidence as justification for destructive automatic response.

## Quick start

Requirements: Python 3.12+, Node.js 22+, npm, Git.

```text
git clone https://github.com/LUKEcheadle-ship-it/quietward-response.git
cd quietward-response
python scripts/bootstrap_local.py
```

Local defaults:

- Frontend: `http://localhost:3001`
- API: `http://localhost:8002`
- API docs: `http://localhost:8002/docs`
- Health: `http://localhost:8002/health`
- Audit verification: `http://localhost:8002/api/v1/audit/verify`

## Enroll a Response agent

Basic agent:

```text
python scripts/enroll_response_agent.py \
  --host-id response-host \
  --token YOUR_ENROLLMENT_TOKEN
```

Opt in to exact-process termination:

```text
python scripts/enroll_response_agent.py \
  --host-id response-host \
  --token YOUR_ENROLLMENT_TOKEN \
  --enable-process-termination
```

Opt in to managed-file quarantine/restore:

```text
python scripts/enroll_response_agent.py \
  --host-id response-host \
  --token YOUR_ENROLLMENT_TOKEN \
  --managed-root /absolute/path/to/managed/data \
  --enable-file-quarantine
```

The helper writes the one-time secret into a permission-hardened private JSON config and does not print it. OS-backed agent secret storage remains a post-alpha hardening target.

Inspect the canonical v1.2 capability surface locally:

```text
python scripts/response_agent_v12.py capabilities --config PATH_TO_AGENT_JSON
```

For normal operation use the capability-aware poller:

```text
python scripts/poll_response_agent.py --config PATH_TO_AGENT_JSON
```

The agent initiates all network connections outward and exposes no inbound command listener.

## Typical workflows

### Suspicious process

1. Run/approve `collect_process_diagnostic`.
2. UI offers eligible unexpired process handles from that same incident/agent.
3. Prepare/approve `terminate_process_by_handle` before its short TTL expires.
4. Agent independently revalidates exact process identity and local capability opt-in.
5. Signed result and audit record return to Response.

### Suspicious file

1. Configure a managed root.
2. Run/approve `collect_file_diagnostic`.
3. Select an eligible file handle from the same incident/agent.
4. Prepare/approve `quarantine_artifact_by_handle`.
5. Preserve the returned rollback handle.
6. Use `restore_quarantined_artifact_by_handle` only when restoration is appropriate.

### Suspicious network activity

1. On a Linux Response agent, run/approve `collect_network_diagnostic`.
2. Review bounded scope/port/state context and hashed remote identity.
3. Correlate with process/host evidence.
4. Network mutation remains manual because firewall/host-isolation executors are intentionally not included in v1.2.

## Core API

Investigation:

- `POST /api/v1/events`
- `GET /api/v1/events`
- `GET /api/v1/hosts`
- `GET /api/v1/hosts/{host_id}`
- `GET /api/v1/incidents`
- `GET /api/v1/incidents/{incident_id}`
- `GET /api/v1/incidents/{incident_id}/response-plan`
- `PATCH /api/v1/incidents/{incident_id}`
- `GET /api/v1/overview`

Controlled response:

- `POST /api/v1/agents/enroll`
- `GET /api/v1/agents`
- `GET /api/v1/agents/{agent_id}`
- `PATCH /api/v1/agents/{agent_id}`
- `POST /api/v1/agents/{agent_id}/capabilities`
- `POST /api/v1/agents/{agent_id}/rotate-key`
- `POST /api/v1/agents/{agent_id}/activate-key`
- `GET /api/v1/actions/registry`
- `POST /api/v1/incidents/{incident_id}/actions`
- `GET /api/v1/incidents/{incident_id}/actions`
- `POST /api/v1/actions/{action_id}/approve`
- `POST /api/v1/actions/{action_id}/reject`
- `GET /api/v1/agents/{agent_id}/actions/pending`
- `POST /api/v1/actions/{action_id}/result`
- `GET /api/v1/audit/verify`
- `GET /api/v1/audit/checkpoint`
- `POST /api/v1/audit/checkpoint/verify`

## v1.2 qualification

Exact clean candidate wrapper:

```text
python scripts/finalize_v12_alpha.py
```

It requires:

1. full backend compile/pytest with warnings treated as errors;
2. public-release/sensitive-persistence audits;
3. exact eight-action static surface verification;
4. fresh and Phase 1→v1.2 Alembic migration qualification;
5. frontend `npm ci`, typecheck, production build and high-severity npm audit;
6. quick-start cleanup smoke;
7. capability-aware live process and file containment acceptance;
8. live Linux privacy-preserving network diagnostic acceptance;
9. audit verification and exactly-once terminal replay checks.

Then perform the browser smoke in `docs/V12_ALPHA_ACCEPTANCE.md` on the exact candidate SHA. Both gates are required before tag/publication.

## Still intentionally unavailable

- arbitrary shell / PowerShell / cmd / bash;
- generic command or script execution;
- raw PID/path/network-target actions;
- general service control;
- firewall/network-rule modification;
- host isolation;
- account/session mutation;
- persistence-object mutation;
- container stop/remove;
- package/configuration mutation;
- autonomous remediation;
- LLM-generated executable commands.

## Known alpha limitations

- analyst auth is bearer RBAC, not enterprise OIDC/SSO;
- browser token is session-scoped JavaScript storage;
- HMAC transport requires TLS outside loopback/trusted development;
- agent secret is permission-hardened JSON unless stronger external secret storage is supplied;
- audit checkpoints are externally retainable tamper anchors, not immutable external storage;
- API qualification remains single process/single worker;
- network diagnostic is Linux-only in v1.2;
- quarantine is limited to configured managed roots and is not an antivirus vault;
- network mutation, identity, persistence, container, service, and package/configuration mutation remain future narrow executors;
- this is not an autonomous remediation system.

Licensed under Apache-2.0.
