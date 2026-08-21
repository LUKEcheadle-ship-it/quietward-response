# QuietWard Response v1.2 alpha threat model

## Security objective

Allow a human analyst to investigate and perform a very small set of real containment actions without turning Response into unrestricted remote administration.

## Trust boundaries

1. **Sensor → Response:** telemetry is untrusted input until validated/authenticated according to source policy. Telemetry can influence incident classification/recommendations but cannot create a new executable action type.
2. **Analyst → Response:** outside loopback development, bearer authentication and RBAC are required. Authenticated identity controls audit attribution.
3. **Response → agent:** the agent initiates outbound polling and HMAC-authenticates every pending/result request. Response exposes no inbound endpoint on the agent.
4. **Agent → local resource:** high-impact actions require an agent-issued opaque handle backed by local identity/fingerprint state.

## Primary attack cases and mitigations

### Malicious telemetry attempts to trigger execution

Mitigations:

- finite action registry;
- persisted incident recommendation binding;
- explicit analyst approval;
- deterministic policy revalidation before dispatch;
- independent agent allowlist;
- no conversion of plan text into commands.

### Analyst identity spoofing

Mitigations:

- non-loopback/non-development startup requires hashed bearer credentials;
- roles are viewer/responder/admin;
- authenticated identity overrides `X-Actor-ID` in audit/write paths;
- machine routes use separate enrollment/HMAC protocols.

Known limitation: bearer RBAC is not enterprise OIDC/SSO yet.

### Raw target injection

Attack examples: server supplies PID 4, `/etc/shadow`, arbitrary service name or shell text.

Mitigations:

- process/file mutators accept exactly one opaque `resource_handle` parameter;
- raw PID/path parameter shapes fail server validation;
- agent validates handle provenance/type/expiry locally;
- generic command/shell action types do not exist.

### Handle theft or cross-incident substitution

Mitigations:

- handles are high-entropy opaque values;
- local context binds each returned handle to incident, host, agent and source action;
- mutating action rejects a handle with missing/local-mismatched provenance;
- short handle/action TTLs reduce replay window;
- consumed handles have deterministic replay receipts rather than performing mutation twice.

### PID reuse / process replacement

Mitigations:

- process identity includes local start/creation/fingerprint data beyond PID;
- identity is re-read immediately before mutation;
- protected/self/parent/critical processes are excluded/refused;
- changed identity fails closed;
- interrupted termination with a vanished/replaced target is reported indeterminate rather than claiming success.

### File path traversal / symlink substitution

Mitigations:

- server cannot submit file paths;
- file handles are issued only for regular files under explicitly configured managed roots;
- symlinks are excluded before resolution;
- root membership + file identity are revalidated before quarantine;
- quarantine directory is forbidden inside managed roots;
- restore requires the rollback handle and refuses occupied/out-of-root targets.

### Crash/retry during mutation

Mitigations:

- agent writes execution intent before mutation;
- resource-handle consumption receipts persist final mutation results;
- quarantine target/rollback handle is deterministic for a source handle;
- exact terminal replay does not repeat mutation;
- ambiguous recovery states fail closed.

### Agent credential compromise

Mitigations:

- HMAC binds method/path/timestamp/nonce/body digest;
- persisted replay nonces;
- agent host binding;
- agent disable cancels pending/approved/pre-execution dispatch;
- endpoint action allowlist and local capability opt-ins.

Known limitation: enrollment helper stores the agent secret in a permission-hardened JSON file rather than an OS key store.

### API flooding / oversized payloads

Mitigations:

- request-size limit before normal schema processing;
- process-local per-client `/api/v1` rate limit;
- existing Pydantic and ActionResult/evidence size bounds.

Known limitation: shared rate limiting is required before multi-worker deployment.

## Qualified mutation scope

v1.2 alpha qualification permits only:

- dedicated demo JSON fixture reset;
- exact test-owned/disposable process termination by handle;
- managed-file quarantine/restore by handle inside configured roots.

The automated live gate must never target arbitrary host files or pre-existing processes.

## Explicitly out of scope

- arbitrary commands/scripts;
- firewall/network isolation;
- arbitrary service control;
- persistence-object mutation;
- account/session mutation;
- container stop/remove;
- package/configuration mutation;
- autonomous remediation;
- multi-worker API runtime;
- immutable external audit retention.

Every future mutator requires its own local identity model, typed parameters, opt-in/risk policy, rollback/failure model, and adversarial qualification before entering the registry.
