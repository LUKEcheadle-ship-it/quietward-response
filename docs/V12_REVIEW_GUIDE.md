# QuietWard Response v1.2.0-alpha.1 reviewer guide

Candidate branch: `feature/response-v12-hardening`

Backend/API version: `1.2.0a1`

## What reviewers are evaluating

QuietWard Response is a standalone incident-investigation and controlled-response platform. v1.2 is the first candidate with narrowly executable real containment, a continuously running endpoint agent, and an optional Response-owned read-only bridge from the separate QuietWard product.

The core release questions are:

> Does v1.2 add useful real response capability without turning the product into unrestricted remote administration?

> Does the combined QuietWard→Response workflow preserve the repository/trust boundary and keep the detector read-only?

Start with `docs/V12_RELEASE_CORRECTIONS.md`; it records the defects found in the full pre-release review and the controls added afterward.

## Review order

### 1. Action and recommendation boundary

Review:

- `backend/app/services/action_registry.py`
- `backend/app/services/policy_service.py`
- `backend/app/services/recommendation_v12.py`
- `backend/app/services/response_plan_v12.py`
- `scripts/response_agent.py`
- `scripts/response_agent_v12.py`

The registry remains finite at eight actions:

1. `restart_quietward_demo_service`
2. `collect_host_diagnostic`
3. `collect_process_diagnostic`
4. `collect_network_diagnostic`
5. `terminate_process_by_handle`
6. `collect_file_diagnostic`
7. `quarantine_artifact_by_handle`
8. `restore_quarantined_artifact_by_handle`

There must be no generic shell, PowerShell, cmd, bash, script, raw PID/path or raw network-target execution API.

Review the post-audit recommendation threshold carefully: generic process/file observations should keep read-only diagnostics but must not automatically expose state-changing process/file containment. Mutation requires the explicit strong evidence documented in `recommendation_v12.py`.

### 2. Incident correlation quality

Review:

- `backend/app/services/correlation_v12.py`
- `backend/app/services/ingestion.py`
- `backend/tests/test_v12_decision_quality.py`

Required behavior:

- same host/time is necessary but not sufficient;
- same category alone does not merge events;
- concrete shared process/file/network/persistence indicators can merge;
- compatible multi-stage attack families can merge only with explicit high-signal evidence plus high/critical severity;
- correlation reasons remain explainable.

Pay particular attention to false merging and false fragmentation.

### 3. Resource identity and containment

Review:

- `scripts/response_agent_resources.py`
- `scripts/response_agent_file_v12.py`
- `backend/tests/test_v12_resource_containment.py`

Required properties:

- opaque `qwrh1_...` handle creation;
- incident/host/agent provenance binding;
- handle expiry and one-time mutation receipts;
- process identity beyond PID;
- Linux pidfd behavior/exit verification;
- protected/self/critical process rejection;
- managed-root file restrictions;
- SHA-256 file-content verification;
- quarantine rollback handles;
- stale/replaced target fail closed;
- 64 MiB per-file diagnostic limit;
- **256 MiB total file-hashing budget per diagnostic action** with explicit truncation counters.

Mutating actions must never accept a server-invented PID/path.

### 4. Continuous endpoint operation and capability truth

Review:

- `scripts/poll_response_agent.py`
- `scripts/response_agent_v12.py`
- `scripts/install_response_agent_user_service.sh`
- `scripts/install_response_agent_windows.ps1`
- `deploy/quietward-response-agent.service`

Required behavior:

- normal poller is long-running; `--once` is diagnostic-only;
- signed capabilities refresh before every poll;
- backoff is bounded;
- SIGTERM/SIGINT stop cleanly;
- Linux/Windows startup remains user-scoped;
- Windows scheduled task is limited-run-level;
- POSIX runtime config loader rejects symlink/public credential files;
- Linux termination is not advertised without pidfd support;
- file mutation is not advertised on unqualified OS families or without managed roots.

### 5. Separate QuietWard integration boundary

Review:

- `scripts/forward_quietward_events.py`
- `scripts/install_quietward_adapter_user_service.sh`
- `scripts/install_quietward_adapter_windows.ps1`
- `deploy/quietward-response-quietward-adapter.service`
- `backend/tests/test_v12_quietward_adapter.py`
- `scripts/verify_v12_quietward_adapter_live.py`

Required properties:

- adapter exists only in this Response repository;
- no import of the QuietWard package;
- detector SQLite opens with `mode=ro` plus `PRAGMA query_only=ON`;
- no detector INSERT/UPDATE/DELETE path;
- enrolled host must match detector host;
- original QuietWard event ID maps deterministically to UUIDv5;
- assessment severity/high-signal context survives translation;
- normal agent HMAC authenticates `source=quietward` ingestion;
- delivery cursor belongs to Response state and advances only after durable/already-durable delivery;
- live gate proves detector DB bytes remain unchanged;
- translated high-signal evidence drives only the same typed Response action surface—never a generic command.

### 6. Network diagnostic privacy

Review `scripts/response_agent_network.py` and tests.

Required properties:

- Linux-only and read-only;
- direct bounded `/proc/net` parsing;
- no subprocess/shell execution;
- maximum 256 public rows;
- no raw local/remote IP, UID or inode in API results;
- concrete remote addresses represented by endpoint-local HMAC-SHA256 pseudonym;
- pseudonym key privately stored only in agent state and never returned;
- firewall/host-isolation mutation remains unavailable.

### 7. Control-plane trust

Review:

- `backend/app/services/analyst_auth.py`
- `backend/app/services/agent_auth.py`
- `backend/app/api/agents.py`
- `backend/app/request_serialization.py`
- `backend/app/services/redaction.py`

Required properties:

- production/non-loopback bearer RBAC;
- responder/admin separation;
- HMAC machine auth and replay protection;
- fresh signed endpoint capability reporting;
- exact-action local enablement;
- disable/reset destroys capability/rotation trust;
- two-phase key rotation with immediate old-key revocation;
- request-size/rate bounds;
- sensitive-field redaction before durable persistence.

### 8. Audit integrity

Review:

- `backend/app/services/audit_service.py`
- `backend/app/api/audit.py`
- `scripts/manage_audit_checkpoint.py`

The ordinary chain remains tamper-evident. A separately retained signed checkpoint additionally detects a consistent historical rewrite or deletion of history already covered by that checkpoint.

Do not interpret checkpoints as immutable/WORM logging.

### 9. Analyst UX

Review:

- `frontend/src/components/ResponseActions.tsx`
- `frontend/src/components/ResponsePlanPanel.tsx`
- `frontend/src/app/agents/page.tsx`

The UI should:

- distinguish read-only diagnostics from state-changing actions;
- show capability freshness;
- avoid free-form PID/path/opaque-handle fields;
- select only unexpired handles from successful prior actions for the same incident/agent;
- keep advisory/manual/planned steps distinct from executable actions;
- not expose termination/quarantine when the stricter incident recommendation did not authorize them.

## Key regression suites

- `backend/tests/test_v12_resource_containment.py`
- `backend/tests/test_v12_agent_capabilities.py`
- `backend/tests/test_v12_agent_key_rotation.py`
- `backend/tests/test_v12_analyst_rbac.py`
- `backend/tests/test_v12_network_diagnostic.py`
- `backend/tests/test_v12_network_agent_integration.py`
- `backend/tests/test_v12_decision_quality.py`
- `backend/tests/test_v12_quietward_adapter.py`
- `backend/tests/test_v12_release_corrections.py`
- `backend/tests/test_v12_audit_checkpoints.py`
- `backend/tests/test_v12_integrity_trust_freeze.py`
- `backend/tests/test_v12_sensitive_redaction.py`
- `backend/tests/test_v12_api_abuse_bounds.py`

`docs/V12_ADVERSARIAL_REGRESSION_MATRIX.md` maps defensive failure modes to tests.

## Reproduce qualification

From an exact clean checkout:

```text
python scripts/finalize_v12_alpha.py
```

The finalizer requires compile/full pytest, tracked-secret/persistence audits, exact eight-action surface validation, release-correction source checks, migrations, frontend dependency/type/build/audit gates, quick-start cleanup, capability-aware live process/file containment, live Linux network diagnostics, **live read-only QuietWard adapter integration**, and final audit/replay checks.

Then complete `docs/V12_ALPHA_ACCEPTANCE.md` on the same SHA, including the continuous agent/platform smoke.

## Questions reviewers should answer

1. Can any telemetry or plan text manufacture a new executable action?
2. Can generic process/file evidence expose a destructive action without the required strong evidence?
3. Can same-category coincidence incorrectly merge incidents?
4. Can the server substitute a raw process/file/network target?
5. Can stale endpoint capability state authorize an action?
6. Can an old credential continue normal traffic after successful rotation?
7. Can a compromised integrity source authorize destructive response against itself?
8. Can the QuietWard adapter modify detector state or bypass the normal authenticated ingestion path?
9. Do file/process executors handle stale/replayed targets safely and within resource budgets?
10. Does the network diagnostic leak reversible remote-address identity?
11. Can a viewer/responder exceed its role?
12. Can audit history be rewritten/truncated without violating a retained checkpoint?
13. Does the normal UI expose any generic-command/raw-target entry point?
14. Does the endpoint remain continuously operational rather than relying on manual polling?

## Known limitations

- experimental alpha, not enterprise SOAR/EDR replacement;
- bearer RBAC is not OIDC/SSO;
- endpoint credential is permission-hardened local JSON rather than OS-backed key storage;
- active server-side symmetric verification key material remains credential-equivalent database data;
- API qualification remains single process/single worker;
- signed checkpoints are not immutable external retention;
- network diagnostic is Linux-only;
- bounded 128-item process/file result sets can require future safe endpoint-side search/filtering on busy hosts;
- quarantine is managed-root containment, not a full antivirus vault;
- a narrow verify→move filesystem race remains documented;
- network mutation, identity/session mutation, persistence control, container mutation and package/config mutation remain intentionally unavailable.

## Review decision

Approve for release only when:

- post-review code/security review finds no remaining release blocker;
- `python scripts/finalize_v12_alpha.py` passes on the exact candidate SHA;
- every required browser/continuous-agent/platform smoke item passes on that same SHA;
- release checklist evidence is recorded before merge/tag/publication.
