# Changelog

All notable changes to QuietWard Response are documented here.

## 1.1.0-alpha.1 — candidate 2026-08-20

First broad incident-response planning alpha candidate. Publication remains blocked until the standalone automated wrapper and browser smoke in `docs/V11_ALPHA_ACCEPTANCE.md` pass on the exact pushed candidate SHA.

### Added

- standalone deterministic response-plan API at `GET /api/v1/incidents/{incident_id}/response-plan`
- response-plan coverage for malware/file, process/privilege, identity/authentication, persistence, network, container, vulnerability/configuration, sensor/evidence-integrity, and operational incidents
- explicit plan priority, objectives, investigation steps, containment steps, recovery steps, escalation conditions, and limitations
- step-state contract distinguishing `available`, `manual`, `planned`, and `blocked` capabilities
- exact `executable_actions` list so advisory containment cannot be mistaken for hidden endpoint automation
- incident-console Response Plan panel with explicit planned/blocked/manual labels
- shared response-family classifier for canonical and common vendor vocabulary including ransomware, credential spray, C2/beaconing, tamper/defense-evasion, Kubernetes/container, CVE, persistence, execution, and outage signals
- bundled Response-owned outward-polling alpha agent implementing only the dedicated demo-fixture action
- private local Response-agent enrollment/config helper that does not print the one-time secret
- standalone live HTTP alpha acceptance using synthetic development telemetry rather than a companion detector checkout
- standalone alpha finalizer and static/local gate

### Hardened

- executable action registry remains exactly the released demo-fixture action
- advisory diagnostic/containment names are rejected if submitted to the action API
- generic command/shell execution remains absent from the bundled Response agent
- Response-agent target, action type, parameters, policy allowance, lifecycle state, expiry, and local recovery history are independently revalidated before execution
- Response-agent demo execution is durable and exactly-once across terminal replay/crash-recovery paths
- ActionResult `result` is capped at 256 KiB serialized and `evidence` at 64 KiB before persistence
- release audit rejects common Response-agent credential/config filenames in tracked files/history
- release-facing docs and gates no longer require or modify any detector repository
- recommendations and probable-cause text are sensor-neutral rather than assuming one detector implementation
- the response-plan API, unit tests, static gate, and live gate share/verify the same high-signal response-family mapping so vendor event names cannot silently downgrade to `unknown`

### Safety boundary

The alpha can recommend broad investigation, containment, and recovery procedures, but those procedures remain clearly manual/planned/blocked. The bundled Response agent exists only to execute the dedicated v1 JSON demo fixture. Real quarantine, process termination, network blocking/isolation, persistence modification, account/session actions, container control, service control, and package/configuration mutation require separate narrow typed executors plus preconditions, rollback/failure semantics, least privilege, and adversarial qualification. There is still no generic shell/PowerShell/cmd/bash, autonomous remediation, or LLM-generated executable command surface.

## 1.0.0 — 2026-08-19

First public release of the end-to-end controlled-response system.

### Added

- versioned sensor-neutral event protocol
- deterministic host/event correlation into explainable incidents
- incident timelines, cause assessment, and rule-based recommendations
- authenticated agent enrollment
- HMAC-SHA256 signed agent events, polling, and action results
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
- deterministic v1 release gate and real HTTP acceptance harness
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
- the release gate verifies that public quick-start smoke leaves frontend port 3001 available after shutdown
- reproducible qualification bootstraps the Python venv/requirements and rebuilds frontend dependencies from `package-lock.json` with `npm ci`
- release-gate npm execution is cross-platform, including Windows `npm.cmd` launch semantics
- finalizer verifies the exact expected GitHub owner/repository, branch, clean tracked state, and untracked `.env` boundary before qualification
- final release qualification cannot silently skip npm audit
- the known development enrollment token is accepted only on a loopback development bind
- event authentication may be disabled only on a loopback development bind
- wildcard CORS is rejected on non-loopback API binds
- unauthenticated generic sensor sources remain development-only
- single-use authenticated nonces even when later business validation rejects the request
- bounded analyst identity headers before database persistence
- authenticated events and ActionResults reject timestamps too far in the future while still allowing legitimate queued older telemetry
- executable actions must be enabled controlled recommendations on the specific incident, with the same binding rechecked before dispatch
- only one active action lifecycle is allowed per incident + host + action type, including during agent credential rotation
- resolved or dismissed incidents reject new response actions and cancel pending/approved/pre-execution-dispatching lifecycles so stale approvals cannot revive later
- disabling an agent cancels pending/approved/pre-execution-dispatching actions so re-enabling the credential cannot revive prior approval state
- expired pending/approved/dispatching actions are surfaced as expired immediately and persisted as expired before a replacement action is created
- private local SQLite and endpoint integration state files where POSIX modes are supported
- request serialization for single-process v1 audit-chain consistency
- `/api/v1` responses are marked `no-store`; one-time enrollment-secret responses also include `Pragma: no-cache`
- frontend API errors preserve useful server conflict/policy details instead of reducing failures to only an HTTP status
- controlled recommendation metadata is preserved through FastAPI response serialization
- dedicated demo incidents keep their response recommendations focused on the demo fixture rather than unrelated operational/disk guidance
- endpoint response state fails closed on corrupt outbox/ledger/demo data and does not silently discard older queued events when the bounded outbox fills
- Docker Compose waits for backend health before starting the frontend service
- release version promotion stamps the actual promotion date instead of a hard-coded development date

### Safety boundary

v1 has no generic shell, PowerShell, cmd, bash, arbitrary process termination, arbitrary service control, file deletion/quarantine, firewall modification, host isolation, or autonomous remediation. The only executable action changes a dedicated JSON demo fixture after human approval, deterministic policy validation, and endpoint-side allowlist validation.

### Release qualification

The historical v1 release qualification used its documented `scripts/finalize_v1.py` wrapper and UI smoke record. v1.1 and later have their own standalone qualification documents and do not require a detector repository checkout.
