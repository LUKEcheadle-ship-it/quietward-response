# QuietWard Response v1.2 adversarial regression matrix

This is the **in-repository defensive regression matrix** for the v1.2 candidate. It is not RedLab and does not perform offensive exploitation. Every case is bounded to API/test-owned state or disposable local fixtures.

A case is release-covered only when its mapped test runs in the full `pytest -W error` gate on the exact candidate SHA.

| ID | Failure / attack attempted | Expected behavior | Primary regression |
|---|---|---|---|
| AUTH-01 | Missing analyst auth outside local-dev boundary | 401 | `test_v12_analyst_rbac.py` |
| AUTH-02 | Invalid bearer plus spoofed actor header | 401; no fallback | `test_v12_analyst_rbac.py` |
| AUTH-03 | Viewer attempts mutation | 403 | `test_v12_analyst_rbac.py` |
| AUTH-04 | Responder attempts admin agent-disable control | 403 | `test_v12_analyst_rbac.py` |
| AGENT-01 | Missing HMAC headers | reject | existing v1 auth tests |
| AGENT-02 | Wrong key ID / signature / body/path | reject | existing v1 auth tests |
| AGENT-03 | Nonce replay | reject | existing v1 auth transaction tests |
| AGENT-04 | Disabled agent requests new trust capability | reject | `test_v12_agent_disable_trust_reset.py` / capability tests |
| CAP-01 | No signed capability report | non-demo action unavailable | `test_v12_agent_capabilities.py` |
| CAP-02 | Exact action locally disabled | action unavailable | `test_v12_agent_capabilities.py` |
| CAP-03 | Capability report older than 15 minutes | action unavailable | `test_v12_agent_capabilities.py` |
| CAP-04 | Capability timestamp too far in future | action unavailable | `test_v12_agent_capabilities.py` |
| CAP-05 | Unknown endpoint action capability | 422 | `test_v12_agent_capabilities.py` |
| CAP-06 | Endpoint claims arbitrary command execution | schema reject | capability schema/tests |
| CAP-07 | Disable then re-enable tries to reuse old capability authority | blocked until fresh report | `test_v12_agent_disable_trust_reset.py` |
| KEY-01 | Pending replacement signs normal API before activation | reject | `test_v12_agent_key_rotation.py` |
| KEY-02 | Current credential attempts replacement activation | reject | `test_v12_agent_key_rotation.py` |
| KEY-03 | Old key used after successful activation | reject immediately | `test_v12_agent_key_rotation.py` |
| KEY-04 | Second rotation overwrites live pending credential | 409 | `test_v12_agent_key_rotation.py` |
| KEY-05 | Expired pending credential activates | reject; current remains | `test_v12_agent_key_rotation.py` |
| KEY-06 | Disabled agent prepares/activates rotation | reject | `test_v12_agent_key_rotation.py` |
| KEY-07 | Disable tries to preserve staged pending replacement | pending state destroyed | `test_v12_agent_disable_trust_reset.py` |
| KEY-08 | Retired HMAC key remains in DB schema | forbidden | `test_v12_migration_contract.py`, `test_v12_agent_key_rotation.py` |
| KEY-09 | Verification material exposed through normal Agent API | forbidden | `test_v12_agent_key_material_exposure.py` |
| HANDLE-01 | Raw PID substituted for opaque process handle | reject | action registry/lifecycle tests |
| HANDLE-02 | Raw filesystem path substituted for opaque file handle | reject | action registry/lifecycle tests |
| HANDLE-03 | Handle reused across incidents | reject locally | `test_v12_resource_containment.py` |
| HANDLE-04 | Expired handle reused | reject | resource-handle tests |
| HANDLE-05 | Resource identity changes after handle issuance | reject | `test_v12_resource_containment.py` |
| PROCESS-01 | PID replaced/reused | fail closed | `test_v12_resource_containment.py` |
| PROCESS-02 | Critical/self/parent process targeted | protected | resource tests / live gate |
| PROCESS-03 | Interrupted termination outcome indeterminate | fail closed, no success claim | resource tests |
| PROCESS-04 | Exact terminal replay | stored receipt; no second termination | resource tests/live gate |
| FILE-01 | Managed file content substituted same size/mtime | SHA-256 identity mismatch | `test_v12_resource_containment.py` |
| FILE-02 | Symlink used as managed file | no handle / reject | `test_v12_resource_containment.py` |
| FILE-03 | Oversized managed file | no handle | `test_v12_resource_containment.py` |
| FILE-04 | Restore destination occupied | reject | `test_v12_resource_containment.py` |
| FILE-05 | Quarantine object modified before restore | reject | resource/live tests |
| FILE-06 | Quarantine/restore terminal replay | deterministic receipt; no duplicate move | resource/live tests |
| TRUST-01 | Evidence-integrity failure exists, process termination requested | policy deny | `test_v12_integrity_trust_freeze.py` |
| TRUST-02 | Evidence-integrity failure exists, read-only diagnostic requested | allowed | `test_v12_integrity_trust_freeze.py` |
| DATA-01 | Password/token in event payload | redacted before persistence | `test_v12_sensitive_redaction.py` |
| DATA-02 | Bearer/password text in event summary | redacted | `test_v12_sensitive_redaction.py` |
| DATA-03 | Token in action result/evidence/error | redacted | `test_v12_sensitive_redaction.py` |
| DATA-04 | Token/password in analyst decision note | redacted | `test_v12_approval_note_redaction.py` |
| DATA-05 | Future caller bypass persists credential-like audit detail | detectable without printing secret | `test_v12_sensitive_persistence_audit_e2e.py` |
| DATA-06 | Agent/staged-rotation config tracked in repo | release audit fail | `test_v12_sensitive_artifact_audit.py`, `audit_v12_sensitive_artifacts.py` |
| API-01 | Advertised oversized request | 413 before schema handling | `test_v12_api_abuse_bounds.py` |
| API-02 | Chunked/no-length body crosses configured bound | stop buffering + reject | `test_v12_chunked_body_bound.py` |
| API-03 | Per-client API rate exhausted | 429 + Retry-After | `test_v12_api_abuse_bounds.py` |
| API-04 | Attacker spoofs X-Forwarded-For to evade limiter | header ignored by limiter | `test_v12_chunked_body_bound.py` source contract |
| AUDIT-01 | Audit row mutation breaks hash chain | verify invalid | existing audit tests |
| AUDIT-02 | Full historical chain consistently recomputed after retained checkpoint | checkpoint mismatch | `test_v12_audit_checkpoints.py` |
| AUDIT-03 | Covered audit suffix deleted | checkpoint truncation failure | `test_v12_audit_checkpoints.py` |
| AUDIT-04 | Checkpoint signature modified | reject | `test_v12_audit_checkpoints.py` |
| AUDIT-05 | Trusted startup checkpoint missing/malformed | startup fail closed | `test_v12_trusted_checkpoint_startup.py` |
| AUDIT-06 | Trusted checkpoint symlink/group-world writable on POSIX | startup reject | `test_v12_trusted_checkpoint_file_safety.py` |
| AUDIT-07 | Legitimate rows appended after retained checkpoint | startup/verification remains valid | `test_v12_trusted_checkpoint_startup.py` |
| UI-01 | Analyst manually types arbitrary PID/path/handle | no normal input exists | frontend safety-label/source tests |
| UI-02 | Stale/un-attested agent presented for non-demo action | filtered/not selectable | frontend safety-label/source tests |
| CMD-01 | Generic `run_shell` / `run_command` action added | registry/surface gate fail | `verify_v12_surface.py`, latest surface tests |
| CMD-02 | Generic subprocess/shell primitive added to Response agent | regression fail | Response-agent source tests |

## Mandatory release interpretation

- `PASS` means the mapped regression actually executed on the candidate SHA.
- A test file existing in GitHub is not itself a qualification result.
- A skipped required containment test blocks the release unless the acceptance document explicitly defines that platform as unsupported for the candidate.
- No case permits testing against arbitrary non-test-owned processes/files.
- No case authorizes generic shell execution, persistence, firewall changes, account mutation, container mutation or host isolation.

## Next matrix expansion

After v1.2 qualifies, new action families must add cases for:

- exact network-rule identity, automatic expiry and rollback;
- persistence-object snapshot/restore;
- container ID + image-digest binding;
- identity/session exact-provider binding and break-glass behavior;
- endpoint private-key / encrypted-key-store compromise and migration failures;
- multi-worker shared replay/rate/audit correctness before multi-worker support is allowed.
