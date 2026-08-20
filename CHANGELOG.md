# Changelog

All notable changes to QuietWard Response are documented here.

## 1.1.0-alpha.1 — candidate 2026-08-20

First expanded-response alpha candidate. Publication remains blocked until the complete alpha wrapper and browser smoke in `docs/V11_ALPHA_ACCEPTANCE.md` pass on the exact pushed candidate branches.

### Added

- eight approval-gated, parameter-free read-only diagnostic response actions for process/privilege, network, persistence, file/malware, container, identity/authentication, vulnerability/configuration, and QuietWard integrity evidence
- incident-to-diagnostic recommendation mapping across QuietWard's major event families
- endpoint-side v1.1 typed diagnostic client that preserves the v1 demo action and rejects arbitrary action types/parameters
- bounded recent-evidence diagnostic results with explicit `read_only=true` and `system_state_changed=false` safety metadata
- dedicated v1.1 action-surface qualification script
- complete v1.1 alpha static/local qualification gate
- live two-repository malware-event-to-diagnostic acceptance loop
- complete alpha finalizer that also reruns the released v1 live demo lifecycle as a regression gate

### Companion QuietWard detection expansion

- bounded same-host multi-stage attack-chain correlation across distinct subjects
- stronger deterministic scoring for large authentication-failure bursts and credential-spray context
- additional priority for existing high-confidence behavioral markers including encoded/download-execute chains, living-off-the-land patterns, cryptomining indicators, and dangerous container configuration markers

### Safety boundary

The only system-state-changing endpoint action remains the dedicated v1 JSON demo fixture. This alpha still adds no generic shell/PowerShell/cmd/bash, process termination, service control, quarantine/deletion, firewall modification, host isolation, account mutation, package mutation, autonomous remediation, or LLM-generated executable command surface.

## 1.0.0 — 2026-08-19

First public release of the end-to-end controlled-response system.

### Added

- versioned sensor-neutral event protocol
- deterministic host/event correlation into explainable incidents
- incident timelines, cause assessment, and rule-based recommendations
- authenticated QuietWard agent enrollment
- HMAC-SHA256 signed QuietWard events, polling, and action results
- persisted nonce replay protection and host binding
- typed, separately versioned ActionRequest / ActionResult protocol
- explicit analyst approval and deterministic action policy
- agent-initiated action polling
- one executable allowlisted demo-fixture action with no arbitrary parameters
- endpoint retry/crash idempotency and duplicate terminal-result checks
- agent disable/re-enable API and console control
- tamper-evident hash-chained audit verification
- Agents and Response Actions analyst UI
- selectable target agent when multiple enabled credentials exist for affected hosts
- PostgreSQL-ready Alembic schema and Docker Compose path
- deterministic v1 release gate and real two-repository HTTP acceptance harness
- one-command local bootstrap that generates a private enrollment token and starts both product surfaces

### Hardened

- frozen Alembic revisions instead of importing mutable current ORM metadata
- normal API startup relies on Alembic instead of silently creating missing schema from mutable ORM metadata
- API startup verifies the existing audit chain and fails closed if tamper evidence is already broken
- consistent runtime/migration `.env` database selection
- combined launcher honors repository `.env` API-port selection
- frontend launcher and enrollment helper follow repository API URL/port overrides instead of silently falling back to port 8002
- combined launcher fails if either backend or frontend exits or never becomes reachable
- native bootstrap isolates and terminates product process groups, and the Unix frontend launcher executes Next directly, so shutdown releases the UI port instead of leaving an orphan server
- the release gate now verifies that public quick-start smoke leaves frontend port 3001 available after shutdown
- reproducible qualification bootstraps the Python venv/requirements and rebuilds frontend dependencies from `package-lock.json` with `npm ci`
- release-gate npm execution is cross-platform, including Windows `npm.cmd` launch semantics
- finalizer verifies the exact expected GitHub owner/repository, Response/QuietWard branches, clean tracked state, and untracked `.env` boundary before qualification
- final release qualification cannot silently skip npm audit
- the known development enrollment token is accepted only on a loopback development bind
- QuietWard event authentication may be disabled only on a loopback development bind
- wildcard CORS is rejected on non-loopback API binds
- unauthenticated generic sensor sources remain development-only
- single-use authenticated nonces even when later business validation rejects the request
- bounded analyst identity headers before database persistence
- authenticated QuietWard events and ActionResults reject timestamps too far in the future while still allowing legitimate queued older telemetry
- executable actions must be enabled controlled recommendations on the specific incident, with the same binding rechecked before dispatch
- only one active action lifecycle is allowed per incident + host + action type, including during agent credential rotation
- resolved or dismissed incidents reject new response actions and cancel pending/approved/pre-execution-dispatching lifecycles so stale approvals cannot revive later
- disabling an agent cancels pending/approved/pre-execution-dispatching actions so re-enabling the credential cannot revive prior approval state
- expired pending/approved/dispatching actions are surfaced as expired immediately and persisted as expired before a replacement action is created
- private local SQLite and endpoint integration state files where POSIX modes are supported
- request serialization for single-process v1 audit-chain consistency
- `/api/v1` responses are marked `no-store`; one-time enrollment-secret responses also include `Pragma: no-cache`
- frontend API errors preserve useful server conflict/policy details instead of reducing failures to only an HTTP status
- QuietWard `info` severity compatibility normalization to canonical `informational`
- controlled recommendation metadata preserved through FastAPI response serialization
- dedicated demo incidents keep their response recommendations focused on the demo fixture rather than unrelated operational/disk guidance
- QuietWard endpoint response state fails closed on corrupt outbox/ledger/demo data and does not silently discard older queued events when the bounded outbox fills
- Docker Compose waits for backend health before starting the frontend service
- release version promotion stamps the actual promotion date instead of a hard-coded development date

### Safety boundary

v1 has no generic shell, PowerShell, cmd, bash, arbitrary process termination, arbitrary service control, file deletion/quarantine, firewall modification, host isolation, or autonomous remediation. The only executable action changes a dedicated JSON demo fixture after human approval, deterministic policy validation, and endpoint-side allowlist validation.

### Release qualification

Release qualification requires both commands to pass on a real checkout:

```bash
python scripts/verify_v1.py --quietward-repo ../quietward
python scripts/verify_v1_live.py --quietward-repo ../quietward
```

The required release wrapper is:

```bash
python scripts/finalize_v1.py --quietward-repo ../quietward
```

The final `1.0.0` commit must pass the complete wrapper and the documented UI smoke check before merge, tag, or public-release publication.
