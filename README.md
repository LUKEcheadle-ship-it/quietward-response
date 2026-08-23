# QuietWard Response

QuietWard Response is a standalone incident-investigation and controlled-response platform. It accepts authenticated security telemetry, correlates observations into incidents, produces deterministic response plans, manages analyst approval and policy, dispatches narrowly typed actions to a Response-owned endpoint agent, and maintains tamper-evident audit records.

It is a **separate product and repository from QuietWard**. Response code does not belong inside the QuietWard repository.

> **Current release candidate:** `v1.2.0-alpha.1` (`1.2.0a1`) on `feature/response-v12-hardening`.
>
> The candidate is still blocked on exact-SHA automated/platform/browser qualification. Feature scope is frozen; only qualification-driven corrections should be added.

## What v1.2 adds

- continuously running capability-aware endpoint agent;
- deterministic incident correlation and response planning;
- stronger v1.2 correlation requiring shared concrete indicators or compatible high-signal attack stages rather than same-category coincidence;
- eight finite approval-gated actions;
- short-lived incident/agent/host-bound opaque resource handles;
- read-only host/process/file diagnostics;
- Linux read-only privacy-preserving network diagnostic;
- opt-in exact-process termination on qualified Linux/Windows hosts;
- reversible managed-file quarantine/restore on Linux/Windows;
- signed endpoint capability negotiation;
- two-phase endpoint-key rotation;
- viewer/responder/admin bearer RBAC;
- request-size/rate bounds;
- sensitive-field redaction before persistence;
- signed externalizable audit checkpoints;
- integrity-compromise mutation freeze;
- optional **Response-owned read-only QuietWard adapter**.

There is still **no generic remote command surface**.

## How QuietWard and Response stay separate

QuietWard remains a public observation-only endpoint monitor. Response is a separate controlled-response product.

When both are used together, this repository provides:

`scripts/forward_quietward_events.py`

The adapter:

- opens the local QuietWard SQLite database with `mode=ro` and `PRAGMA query_only=ON`;
- never imports the QuietWard Python package;
- never writes QuietWard tables;
- validates that the detector host matches the enrolled Response agent host;
- deterministically maps QuietWard event IDs to retry-safe UUIDv5 Response IDs;
- preserves stored assessment severity and bounded evidence;
- submits `source=quietward` through the normal HMAC-authenticated Response agent credential;
- stores only its own private delivery cursor under Response agent state.

This keeps the two repositories independent while providing a qualified integration boundary.

## Response coverage

`GET /api/v1/incidents/{incident_id}/response-plan`

Plans cover malware/ransomware, execution/privilege, identity attacks, persistence, network/C2 activity, containers/Kubernetes, vulnerabilities/configuration, evidence/sensor integrity and operational failures.

Every plan separates investigation, containment, recovery, escalation and the exact executable action list. Planned/manual/blocked guidance is not executable code.

### Correlation policy

v1.2 does **not** merge incidents merely because two events share a category.

Correlation requires either:

- a shared concrete process/file/network/persistence indicator; or
- a compatible attack-stage transition where at least one side contains explicit high-signal evidence and the highest evidence severity is high/critical.

This is intentionally stricter than the earlier broad same-category correlation behavior.

## v1.2 action surface

The registry is explicit and finite:

| Action | Type | Qualified targeting |
|---|---|---|
| `restart_quietward_demo_service` | demo state change | no parameters |
| `collect_host_diagnostic` | read-only | no parameters |
| `collect_process_diagnostic` | read-only | bounded Linux/Windows process snapshot; issues handles |
| `collect_network_diagnostic` | read-only | Linux `/proc/net`; no raw network target |
| `terminate_process_by_handle` | high-impact containment | Linux/Windows opaque process handle only |
| `collect_file_diagnostic` | read-only | Linux/Windows configured managed roots only |
| `quarantine_artifact_by_handle` | reversible containment | Linux/Windows managed-file handle only |
| `restore_quarantined_artifact_by_handle` | rollback | Linux/Windows rollback handle only |

Every registered action requires analyst approval and deterministic server policy.

There is no shell, PowerShell, cmd, bash, generic script, raw PID, raw filesystem path or raw network-target execution API.

### High-impact recommendation threshold

Read-only investigation remains broad. Mutating actions require stronger evidence:

`terminate_process_by_handle` is exposed only for:

- high/critical privilege escalation; or
- high/critical process execution with explicit high-signal evidence such as reverse shell, credential dumping/theft, process injection, web shell, suspicious document/interpreter ancestry or ransomware-impact behavior.

File quarantine/restore is exposed only for:

- malware-signature or YARA evidence;
- high/critical newly created executable evidence; or
- high/critical file evidence with an explicit known-bad-hash marker.

A generic process start or generic file change does not expose destructive containment.

## Opaque resource handles

A Response agent creates random `qwrh1_...` handles from its own local observation of a resource. The control plane cannot invent a PID, file path or socket identity.

Handles are:

- local to the agent;
- incident/host/agent provenance-bound;
- short-lived;
- single-consumption for mutating operations;
- revalidated against current local identity before mutation.

Process termination and quarantine action TTLs are capped at 240 seconds. Normal analyst UI offers only unexpired handles returned by successful prior actions for the same incident and selected agent; it does not expose a free-form PID/path/handle target box.

## Process containment boundary

Process diagnostics and exact-process termination are qualified only for Linux/Windows candidate paths.

The agent:

- returns a bounded process snapshot;
- protects its own process/parent and critical OS processes;
- binds handles to identity data beyond PID;
- revalidates identity immediately before termination;
- rejects stale/reused PID identities;
- uses pidfd-bound signaling on Linux when available;
- performs bounded exit verification;
- fails closed when an interrupted outcome is indeterminate.

Linux termination is not advertised in signed endpoint capabilities when pidfd support is unavailable. High-impact termination is disabled by default in local config.

## File containment boundary

File diagnostics/quarantine operate only inside explicitly configured Response-agent managed roots on Linux/Windows.

The agent:

- excludes symbolic links;
- never accepts a server-supplied path;
- binds identity to filesystem metadata plus SHA-256 content;
- caps each eligible file at 64 MiB;
- caps total file hashing per diagnostic action at **256 MiB**;
- reports scanned bytes/budget/truncation;
- revalidates before quarantine and verifies after the move;
- creates a separate rollback handle;
- refuses restore when the original path is occupied/outside the root or the quarantine object changed;
- records consumption receipts so terminal replay does not repeat mutation.

The remaining documented file limitation is the narrow same-user filesystem race between final identity verification and a portable cross-platform move. Platform-specific descriptor/handle-relative hardening remains future work.

## Network diagnostic boundary

`collect_network_diagnostic` is **Linux-only and read-only**.

It reads bounded `/proc/net/{tcp,tcp6,udp,udp6}` state directly without invoking a shell/subprocess and returns at most 256 rows containing protocol/family, local/remote scope, ports, state, an endpoint-local keyed remote-address pseudonym and a short-lived local socket handle.

Raw local/remote IPs, socket UID and inode stay local to the agent. A private random 32-byte key in the Response-agent state directory drives HMAC-SHA256 pseudonyms, preventing the server from receiving a brute-forceable plain IP digest while retaining same-endpoint correlation.

Firewall changes and host isolation are not available in v1.2.

## Continuous endpoint agent

Normal operation is continuous:

```text
python scripts/poll_response_agent.py --config PATH_TO_AGENT_JSON
```

The agent:

- refreshes signed capability state before every poll;
- polls on a bounded interval;
- exits cleanly on SIGTERM/SIGINT;
- uses bounded exponential backoff during API/network failure;
- exposes `--once` only for diagnostics/qualification.

User-scoped deployment helpers:

Linux:

```text
./scripts/install_response_agent_user_service.sh /absolute/path/to/agent.json
```

Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_response_agent_windows.ps1 -ConfigFile C:\absolute\path\agent.json
```

The Windows path uses a limited current-user scheduled task. The Linux path uses a user systemd service with `NoNewPrivileges=true` and other service hardening.

The runtime config loader rejects relative, symlinked, abnormal, oversized and group/world-readable POSIX credential files. OS-backed secret storage remains a later hardening target.

## Install the optional QuietWard adapter

Enroll the Response agent using the **exact QuietWard host ID**. Then install the read-only adapter.

Linux default QuietWard DB path:

```text
./scripts/install_quietward_adapter_user_service.sh \
  /absolute/path/to/agent.json \
  /home/USER/.local/state/quietward/quietward.sqlite3
```

Windows default installed QuietWard DB path:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_quietward_adapter_windows.ps1 `
  -ConfigFile C:\absolute\path\agent.json `
  -QuietWardDatabase "$env:LOCALAPPDATA\QuietWard\state\quietward.sqlite3"
```

By default the adapter starts from the current end of the QuietWard event table and forwards future events. `--from-beginning` is available for deliberate backfill. Deterministic Response UUIDs make retry/DB-reset replay idempotent.

## Signed endpoint capabilities

Agents sign supported and locally enabled action sets to:

`POST /api/v1/agents/{agent_id}/capabilities`

The report attests `arbitrary_command_execution=false` and uses the `qwrh1` handle protocol.

Server policy refuses non-demo actions when capability state is missing, older than 15 minutes, implausibly future-dated or does not enable the exact action. The endpoint remains the final independent allowlist authority.

## Agent credential rotation

Use:

```text
python scripts/rotate_response_agent_key.py --config PATH_TO_AGENT_JSON
```

Rotation is prepare → prove replacement → activate. A private `.next` sidecar is written before activation; activation immediately revokes the old credential for normal HMAC traffic; the promoted key then proves normal capability traffic before `.next` replaces the original config.

Recover an interrupted staged rotation with:

```text
python scripts/rotate_response_agent_key.py --config PATH_TO_AGENT_JSON --recover-next
```

Retired HMAC secret material is not persisted after activation. One-time secrets are not printed by helpers or returned in normal listings/audit details.

## Analyst authentication and RBAC

Loopback development retains the local `X-Actor-ID` convenience path.

Outside loopback development, Response will not start without `QWR_ANALYST_CREDENTIALS`.

Roles:

- `viewer` — read-only;
- `responder` — incident changes plus action create/approve/reject;
- `admin` — responder plus agent enable/disable and other explicit administrative mutation endpoints.

Generate a high-entropy token/hash entry:

```text
python scripts/generate_analyst_token.py --actor-id alice --role admin
```

Configuration stores only the SHA-256 token hash. TLS remains required outside trusted loopback development.

## Audit/evidence hardening

Sensitive credential-like fields are centrally redacted before new audit/event/action-note persistence.

The database audit trail is hash chained. v1.2 also supports externally retainable HMAC-signed checkpoints:

- `GET /api/v1/audit/checkpoint`
- `POST /api/v1/audit/checkpoint/verify`

A retained signed checkpoint can detect ordinary chain tamper, consistent full-history recomputation after the checkpoint, deletion/truncation of already-checkpointed history and checkpoint signature tamper.

Production/non-loopback deployments must replace the development checkpoint secret using `QWR_AUDIT_CHECKPOINT_SECRET`. A trusted retained checkpoint can also be required at startup via `QWR_TRUSTED_AUDIT_CHECKPOINT_PATH`.

This is stronger tamper evidence, not immutable/WORM external storage.

## API abuse bounds

The qualified v1.2 runtime remains single process/single worker and applies:

- request-size limit (default 1 MiB);
- per-client `/api/v1` process-local rate limit (default 600/minute);
- bounded ActionResult/evidence sizes;
- `no-store`, `nosniff`, frame, referrer and permissions-policy headers.

Shared multi-worker rate/audit/replay primitives remain post-alpha work.

## Integrity trust freeze

When an incident contains explicit sensor/evidence integrity compromise, medium/high/critical state-changing actions are blocked by deterministic policy. Read-only investigation remains available.

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

Enroll an agent:

```text
python scripts/enroll_response_agent.py \
  --host-id HOST_ID \
  --token YOUR_ENROLLMENT_TOKEN
```

Opt-in flags remain available for process termination and configured managed-file quarantine. Inspect the canonical signed-capability surface locally with:

```text
python scripts/response_agent_v12.py capabilities --config PATH_TO_AGENT_JSON
```

## Runtime health truth

`GET /health` reports:

- `response_scope=typed_controlled_response_v12`;
- finite action counts;
- `generic_command_execution=false`;
- `single_worker_required=true`.

The backward-compatible `remediation_enabled=false` field means arbitrary/general host remediation is still disabled; it does not mean the finite registered v1.2 controlled actions are absent.

## Qualification

Exact clean candidate wrapper:

```text
python scripts/finalize_v12_alpha.py
```

It requires:

1. full backend compile/pytest with warnings treated as errors;
2. secret/artifact and durable sensitive-persistence audits;
3. exact eight-action surface verification;
4. release-correction daemon/adapter/decision/privacy source gate;
5. fresh and Phase 1→v1.2 Alembic migration qualification;
6. frontend `npm ci`, typecheck, production build and high-severity npm audit;
7. quick-start cleanup smoke;
8. capability-aware live process/file containment;
9. live Linux privacy-preserving network diagnostic;
10. live read-only QuietWard SQLite → authenticated Response incident/plan acceptance;
11. audit verification and exactly-once terminal replay checks.

Then perform every browser-smoke item in `docs/V12_ALPHA_ACCEPTANCE.md` on the **same exact candidate SHA**.

See:

- `docs/V12_REVIEW_GUIDE.md`
- `docs/V12_RELEASE_CORRECTIONS.md`
- `docs/V12_ALPHA_THREAT_MODEL.md`
- `docs/V12_ADVERSARIAL_REGRESSION_MATRIX.md`
- `docs/V12_RELEASE_CHECKLIST.md`
- `docs/releases/v1.2.0-alpha.1.md`

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
- HMAC transport requires TLS outside loopback/trusted development;
- endpoint secret remains permission-hardened local JSON rather than OS-backed credential storage;
- active server-side symmetric agent verification keys remain credential-equivalent DB material;
- audit checkpoints require genuinely independent retention to protect against DB rewrite/truncation;
- API qualification remains single process/single worker;
- network diagnostic is Linux-only;
- process/file diagnostics are intentionally bounded and may require future safe endpoint-side filtering/search on very busy hosts;
- quarantine is limited to configured managed roots and is not an antivirus vault;
- a narrow same-user verify→move filesystem race remains documented;
- network mutation, identity, persistence, container, service and package/configuration mutation remain future narrow executors;
- this is not an autonomous remediation system.

Licensed under Apache-2.0.
