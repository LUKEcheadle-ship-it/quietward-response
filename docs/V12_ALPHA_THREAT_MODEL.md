# QuietWard Response v1.2 alpha threat model

## Security objective

Allow a human analyst to investigate and perform a very small set of real containment actions without turning Response into unrestricted remote administration.

## Trust boundaries

1. **Sensor → Response:** telemetry is untrusted input until validated/authenticated according to source policy. Telemetry can influence incident classification/recommendations but cannot create a new executable action type.
2. **Analyst → Response:** outside loopback development, bearer authentication and RBAC are required. Authenticated identity controls audit attribution.
3. **Response → agent:** the agent initiates outbound polling and HMAC-authenticates pending/result traffic. Response exposes no inbound endpoint on the agent.
4. **Agent capability state → policy:** the agent signs its supported and locally enabled action set. Server policy cannot assume a v1.2 capability the endpoint has not attested as enabled.
5. **Agent → local resource:** high-impact actions require an agent-issued opaque handle backed by local identity/fingerprint state.
6. **Audit DB → retained checkpoint:** the in-database hash chain is tamper-evident. A separately signed audit checkpoint may be retained outside the DB to anchor a historical prefix against later consistent rewrite or truncation.

## Primary attack cases and mitigations

### Malicious telemetry attempts to trigger execution

Mitigations:

- finite action registry;
- persisted incident recommendation binding;
- explicit analyst approval;
- deterministic policy revalidation before dispatch;
- signed endpoint capability negotiation;
- independent agent allowlist;
- no conversion of plan text into commands.

### Analyst identity spoofing

Mitigations:

- non-loopback/non-development startup requires hashed bearer credentials;
- roles are viewer/responder/admin;
- authenticated identity overrides `X-Actor-ID` in audit/write paths;
- machine routes use separate enrollment/HMAC protocols.

Known limitation: bearer RBAC is not enterprise OIDC/SSO yet.

### Server assumes or enables endpoint capability

Attack: a compromised/misconfigured control plane attempts to dispatch process termination or quarantine to an endpoint whose local config did not enable it.

Mitigations:

- agent signs `supported_actions` and `enabled_actions` to its capability endpoint;
- enabled actions must be a subset of the finite registered action set;
- unknown capability names such as a hypothetical shell action are rejected;
- the report explicitly attests `arbitrary_command_execution=false` and the `qwrh1` resource-handle protocol;
- server policy rejects non-demo v1.2 actions if no capability report exists or if the action is absent from `enabled_actions`;
- the normal incident UI offers only agents that signed the selected action as enabled;
- endpoint-side local feature flags and allowlists remain the final independent authority even after server policy passes.

Residual risk: capability state is a signed statement from the endpoint, not remote attestation of the endpoint binary or OS. A fully compromised endpoint possessing its own credential can lie about its local state. That endpoint is already inside the Response-agent trust boundary and should be disabled/re-enrolled after compromise.

### Raw target injection

Attack examples: server supplies PID 4, `/etc/shadow`, arbitrary service name or shell text.

Mitigations:

- process/file mutators accept exactly one opaque `resource_handle` parameter;
- raw PID/path parameter shapes fail server validation;
- agent validates handle provenance/type/expiry locally;
- normal console flow offers only unexpired handles returned by successful prior actions for the same incident and selected agent;
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
- Linux process termination uses a pidfd bound to the process instance, then verifies the exact identity is gone;
- Windows revalidates process creation identity on the opened termination handle and performs a bounded exit wait;
- protected/self/parent/critical processes are excluded/refused;
- changed identity fails closed;
- interrupted termination with a vanished/replaced target is reported indeterminate rather than claiming success.

### File path traversal / symlink substitution

Mitigations:

- server cannot submit file paths;
- file handles are issued only for regular files under explicitly configured managed roots;
- symlinks are excluded before resolution;
- root membership, filesystem identity, metadata and SHA-256 content are revalidated before containment;
- content is verified again after quarantine/restore;
- quarantine directory is forbidden inside managed roots;
- restore requires the rollback handle and refuses occupied/out-of-root targets.

Residual risk: on portable cross-platform filesystems, verification and the final move are not one atomic primitive. A malicious local actor with equivalent filesystem access could race the final operation. Device/inode/metadata/content checks plus post-move verification narrow this window; platform-specific descriptor/handle-relative operations are future hardening.

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
- endpoint action allowlist and local capability opt-ins;
- agent-initiated credential rotation is available without exposing a replacement secret in normal API listings/audit records.

#### Rotation hijack / crash recovery

The rotation protocol is intentionally two phase:

1. only the **current** credential can request `rotate-key`, which creates a short-lived pending credential without changing the active key;
2. the pending secret is written to a private `.next` sidecar before activation;
3. only the **pending** credential can sign `activate-key` and prove possession of the replacement secret;
4. after activation, the old current key becomes a bounded five-minute previous-key recovery credential;
5. a previous grace credential may finish normal signed traffic but **cannot prepare another rotation**;
6. after activation, the helper proves the new current key with a signed capability sync and atomically promotes `.next` over the old private config;
7. if activation/promotion is interrupted, `--recover-next` can retry using the staged secret without printing it.

This prevents a stolen previous grace key from repeatedly rotating/hijacking the current credential while still providing a bounded post-activation recovery path.

Known limitation: the private agent config/`.next` secret is permission-hardened local JSON rather than an OS-backed secret store. OS credential storage remains post-alpha hardening.

### API flooding / oversized payloads

Mitigations:

- request-size limit before normal schema processing;
- process-local per-client `/api/v1` rate limit;
- existing Pydantic and ActionResult/evidence size bounds.

Known limitation: shared rate limiting is required before multi-worker deployment.

### Full audit-chain rewrite

Attack: an attacker with database write access changes historical audit content and recomputes every subsequent `previous_hash`/`entry_hash`, leaving the database internally consistent.

Mitigations:

- ordinary `verify_audit_chain` still detects accidental/partial tamper;
- a separately configured audit-checkpoint secret signs `(generated_at, entries_checked, head_hash)`;
- a checkpoint retained outside the database anchors the exact historical prefix;
- later verification authenticates the checkpoint and compares the checkpoint head to the same prefix in the current DB;
- a consistently recomputed historical prefix therefore fails the retained checkpoint even when the plain chain is internally valid.

Residual risk: if the attacker also compromises the independent checkpoint secret and every retained external checkpoint, they can forge a replacement anchor.

### Audit suffix deletion

Attack: records after some point are removed while the remaining prefix stays internally valid.

Mitigation: any retained checkpoint covering more entries than the current DB detects the missing/truncated prefix. A checkpoint generated before the deleted records obviously cannot prove records it never covered.

### Checkpoint tampering

Mitigation: HMAC-SHA256 signature using a key derived from the independent `QWR_AUDIT_CHECKPOINT_SECRET`; malformed/signature-modified checkpoints fail closed.

Known limitation: signed checkpoints strengthen tamper evidence but are not immutable external/WORM retention. Operational value depends on exporting/retaining them somewhere independent of the database.

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
- immutable external/WORM audit retention.

Every future mutator requires its own local identity model, typed parameters, opt-in/risk policy, rollback/failure model, and adversarial qualification before entering the registry.
