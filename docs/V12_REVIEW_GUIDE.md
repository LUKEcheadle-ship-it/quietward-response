# QuietWard Response v1.2.0-alpha.1 reviewer guide

Candidate branch: `feature/response-v12-hardening`

Backend/API version: `1.2.0a1`

## What reviewers are evaluating

QuietWard Response is a standalone incident-investigation and controlled-response platform. v1.2 is the first candidate with narrowly executable real containment in addition to deterministic response planning.

The core release question is:

> Does v1.2 add useful real response capability without turning the product into unrestricted remote administration?

## Review order

### 1. Action boundary

Start with:

- `backend/app/services/action_registry.py`
- `backend/app/services/policy_service.py`
- `scripts/response_agent.py`
- `scripts/response_agent_v12.py`
- `scripts/response_agent_resources.py`
- `scripts/response_agent_network.py`
- `docs/V12_ALPHA_THREAT_MODEL.md`
- `docs/V12_ADVERSARIAL_REGRESSION_MATRIX.md`

The registry must remain finite and typed. v1.2 has eight registered actions:

1. `restart_quietward_demo_service`
2. `collect_host_diagnostic`
3. `collect_process_diagnostic`
4. `collect_network_diagnostic`
5. `terminate_process_by_handle`
6. `collect_file_diagnostic`
7. `quarantine_artifact_by_handle`
8. `restore_quarantined_artifact_by_handle`

There must be no generic shell, PowerShell, cmd, bash, script, raw PID/path or raw network-target execution API.

### 2. Resource identity and containment

Review:

- opaque `qwrh1_...` handle creation;
- incident/host/agent provenance binding;
- handle expiry and one-time mutation receipts;
- process start/creation identity beyond PID;
- Linux pidfd behavior and exit verification;
- managed-root file restrictions;
- SHA-256 file-content verification;
- quarantine rollback handles;
- stale/replaced target fail-closed behavior.

Mutating actions must never accept a server-invented PID/path.

### 3. Network diagnostic privacy

Review `scripts/response_agent_network.py` and its tests.

Required properties:

- Linux-only and read-only;
- direct bounded `/proc/net` parsing;
- no subprocess/shell execution;
- maximum 256 public rows;
- no raw local/remote IP, UID or inode in API results;
- concrete remote addresses are represented by an endpoint-local HMAC-SHA256 pseudonym;
- the pseudonym key is stored privately in the agent state directory and never returned to Response;
- firewall/host-isolation mutation remains unavailable.

### 4. Control-plane trust

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
- request-size and rate bounds;
- sensitive-field redaction before durable persistence.

### 5. Audit integrity

Review:

- `backend/app/services/audit_service.py`
- `backend/app/api/audit.py`
- `scripts/manage_audit_checkpoint.py`

The ordinary chain must remain tamper-evident. A separately retained signed checkpoint should additionally detect a consistent historical rewrite or deletion of history already covered by that checkpoint.

Do not interpret checkpoints as immutable/WORM logging.

### 6. Analyst UX

Review:

- `frontend/src/components/ResponseActions.tsx`
- `frontend/src/components/ResponsePlanPanel.tsx`
- `frontend/src/app/agents/page.tsx`

The UI should:

- visibly distinguish read-only diagnostics from state-changing actions;
- show capability freshness;
- avoid free-form PID/path/opaque-handle fields;
- select only unexpired handles from successful prior actions for the same incident and agent;
- keep advisory/manual/planned steps distinct from executable actions.

## Key adversarial suites

- `backend/tests/test_v12_resource_containment.py`
- `backend/tests/test_v12_agent_capabilities.py`
- `backend/tests/test_v12_agent_key_rotation.py`
- `backend/tests/test_v12_analyst_rbac.py`
- `backend/tests/test_v12_network_diagnostic.py`
- `backend/tests/test_v12_network_agent_integration.py`
- `backend/tests/test_v12_audit_checkpoints.py`
- `backend/tests/test_v12_integrity_trust_freeze.py`
- `backend/tests/test_v12_sensitive_redaction.py`
- `backend/tests/test_v12_api_abuse_bounds.py`

`docs/V12_ADVERSARIAL_REGRESSION_MATRIX.md` maps the expected defensive failure modes to tests.

## Reproduce qualification

From an exact clean checkout:

```text
python scripts/finalize_v12_alpha.py
```

The finalizer requires:

- compile + full pytest with warnings as errors;
- tracked-secret and sensitive-persistence audits;
- exact eight-action surface validation;
- fresh and historical migrations;
- frontend `npm ci`, typecheck, production build and high-severity audit;
- quick-start cleanup smoke;
- capability-aware live process/file containment;
- live Linux network-diagnostic acceptance;
- audit verification and terminal replay checks.

Then complete the browser smoke in `docs/V12_ALPHA_ACCEPTANCE.md` on the same SHA.

## Questions reviewers should answer

1. Can any telemetry or plan text manufacture a new executable action?
2. Can the server substitute a raw process/file/network target?
3. Can stale endpoint capability state authorize an action?
4. Can an old credential continue normal traffic after successful rotation?
5. Can a compromised integrity source authorize destructive response against itself?
6. Do file/process executors handle stale/replayed targets safely?
7. Does the network diagnostic leak reversible remote-address identity?
8. Can a viewer/responder exceed its role?
9. Can audit history be rewritten/truncated without violating a retained checkpoint?
10. Does the normal UI expose any generic-command or raw-target entry point?

## Known limitations

- experimental alpha, not enterprise SOAR/EDR replacement;
- bearer RBAC is not OIDC/SSO;
- agent credential is permission-hardened JSON rather than OS-backed key storage;
- API qualification remains single process/single worker;
- signed checkpoints are not immutable external retention;
- network diagnostic is Linux-only;
- quarantine is managed-root containment, not a full antivirus vault;
- network mutation, identity/session mutation, persistence control, container mutation and package/config mutation remain intentionally unavailable.

## Review decision

Approve for release only when:

- security/code review finds no control-boundary regression;
- `python scripts/finalize_v12_alpha.py` passes on the exact candidate SHA;
- every required browser-smoke item passes on that same SHA;
- release checklist evidence is recorded before merge/tag/publication.
