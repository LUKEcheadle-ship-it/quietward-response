# Threat model

## Assets and trust boundaries

Protected assets include event integrity, incident state, analyst decisions, audit history, agent credentials, approval state, and action/result integrity. Sensor payloads cross an untrusted boundary before validation. The browser, API, database, QuietWard agent, and action execution fixture are separate trust zones.

v1 remains local/trusted-network development software. Public Internet exposure or placement behind an untrusted reverse proxy is outside the supported boundary.

## v1 security model

- QuietWard agents enroll with an explicit local enrollment token.
- Enrollment returns a secret once; the server stores derived HMAC key material, not the original enrollment secret. The derived key is still secret-equivalent and must be protected.
- QuietWard event delivery, agent polling, and action-result submission use HMAC-SHA256 request authentication.
- Signed requests bind method, path/query, timestamp, nonce, and body hash.
- A bounded timestamp window and persisted `(agent_id, nonce)` values provide replay resistance.
- Response is represented only as versioned typed actions.
- Both server and agent maintain explicit allowlists. There is no shell/exec/run-command action.
- The only executable v1 action is `restart_quietward_demo_service`, which changes only a dedicated QuietWard-owned JSON demo fixture. It does **not** control an operating-system service.
- Execution requires stored human approval and a deterministic policy decision before agent polling can retrieve a new action.
- Agents initiate outbound polling; QuietWard does not expose a remote command listener.
- Audit records are hash-chained for tamper evidence. This detects many modifications but does not make a locally controlled database immutable.
- Local SQLite data and QuietWard response-state files are written with private-file permissions where POSIX permission semantics are available.

## Threats and controls

### Forged events

An attacker could submit fabricated evidence. Events claiming `source=quietward` require an enabled enrolled agent, valid key ID, HMAC signature, matching enrolled host, fresh timestamp, and unused nonce. Schema validation and global event UUID idempotency still apply. Other synthetic/development sources remain usable for local demos and are not equivalent to authenticated QuietWard telemetry.

Residual risk: a compromised legitimate QuietWard agent can still sign false telemetry. Cross-sensor corroboration, agent health scoring, automated revocation workflows, and transport identity beyond shared-secret HMAC remain future work.

### Stolen agent secret

Possession of the derived HMAC key or original enrollment secret permits an attacker to impersonate that agent within the replay window. The current design limits the credential to one enrolled agent/host and supports disabling the agent record, but automated rotation/revocation is not yet implemented.

Mitigations for deployment: store endpoint secrets with OS-protected secret storage, use TLS, rotate keys, revoke suspected agents, and avoid copying credentials into logs or source control.

### Replay attacks

Every authenticated request includes a timestamp and cryptographically random nonce. The server rejects requests outside the configured replay window and rejects a nonce previously used by the same agent. Event UUID idempotency provides an additional layer for event delivery.

A network timeout can occur after the server commits an event but before QuietWard receives the HTTP response. On retry the server returns duplicate-ID conflict; QuietWard recognizes the specific `duplicate_event_id` response as successful completion so the event outbox does not remain permanently stuck.

Residual risk: nonce persistence is database-backed and designed for local scale rather than a horizontally distributed API. A future clustered deployment needs a shared atomic replay store.

### Tampered request body or action substitution

The HMAC includes a SHA-256 digest of the exact request body plus method and target path/query. Changing the event, result, requested resource, or endpoint invalidates the signature. Action requests are never supplied by the endpoint itself; the server returns only persisted typed actions addressed to that agent.

A new action is returned only after approval and policy evaluation. An action already in `executing` may be returned again to the same authenticated endpoint strictly for crash/retry reconciliation.

### Forged ActionResult

Action results are accepted only over an authenticated agent request. The `agent_id`, `host_id`, URL action ID, and stored action target must all agree. Results for unknown actions or another agent/host are rejected. A completed action cannot be changed to another terminal status.

A repeated terminal result is accepted only when status, structured result, error, and evidence match what Response already stored. A conflicting duplicate terminal result is rejected.

### Duplicate action execution and crash recovery

The endpoint persists an `executing` intent before attempting local execution. The dedicated demo fixture stores the applied `action_id` and prior structured result, and the endpoint also keeps a durable terminal-result ledger.

If a process or network failure occurs after the local fixture changed but before Response received the final result, Response can re-deliver the same `executing` action to the same authenticated agent. QuietWard sees the fixture's matching action ID and returns the previously applied result instead of applying the change again. A terminal action present in the ledger is likewise re-reported instead of re-executed.

This gives the single v1 demo action explicit crash/retry idempotency. Future high-impact executors should use transactional durable execution journals appropriate to their target resources rather than assuming this fixture mechanism generalizes automatically.

### Approval bypass

The server refuses dispatch when the action is unregistered, parameters are invalid, target agent/host do not match the incident, the action or approval is expired, the agent is disabled, or the approval is not approved. Expired approval state is persisted rather than rolled back. The agent separately rejects unknown types, non-empty parameters, wrong host, and wrong agent.

Current limitation: local analyst identity is represented by `X-Actor-ID` and is not yet backed by OIDC/RBAC. v1 therefore proves the approval state machine and security boundary, not production analyst authentication.

### Malicious or compromised Response server

A compromised server can attempt to send malicious action data, but the v1 QuietWard executor only recognizes one hard-coded demo action, requires its own exact host/agent identifiers, accepts no parameters, and refuses arbitrary paths/service names/commands. This materially limits the blast radius of a server compromise in v1.

A future real remediation library must preserve endpoint-side allowlisting, scoped capabilities, expiry, least privilege, and independent validation.

### Compromised QuietWard endpoint

A compromised endpoint can forge signed telemetry and ActionResults using its local credential. It cannot directly create analyst approvals through the agent-authenticated endpoints. The system should treat endpoint evidence as an authenticated claim, not unquestionable truth.

### API compromise

Safe defaults include loopback binding, narrow CORS, strict Pydantic envelopes, parameterized SQLAlchemy queries, no raw shell surface, environment-only secrets, typed action schemas, and agent-initiated polling. Non-development configuration rejects the known development enrollment token.

Production deployment still requires TLS, authenticated analyst sessions/RBAC, rate limits, security headers, key rotation, CSRF strategy where applicable, and deployment hardening.

### Audit-log tampering

v1 hash-chains audit entries using canonicalized record contents plus the previous entry hash. `/api/v1/audit/verify` recalculates the chain and reports mismatches. New audit timestamps are kept strictly monotonic so clock equality or small backwards movement cannot reorder appended records during verification. Legacy Phase 1 rows can be backfilled once when all existing rows are unhashed; partially hashed history is not silently rewritten.

This provides tamper **evidence**, not immutability. A database administrator can modify records and hashes together or delete a suffix of the chain. Future work should sign periodic checkpoints and export them to an external append-only/write-once store.

### Privilege escalation

The Response server needs no endpoint privileges. QuietWard's only v1 executor changes a dedicated state file in its own configured state directory. It invokes no shell, service manager, firewall tool, process-kill API, or privileged command. Future host remediation must be isolated into a narrow privileged broker rather than expanding the investigation API's privileges.

### Data leakage

Events may contain sensitive operational evidence. The application stores accepted fields as submitted. Local SQLite files are permission-hardened where supported, and QuietWard's event outbox/action ledger/demo fixture are written as private files on POSIX systems. These controls do not replace full at-rest encryption or OS secret storage.

Deployments must protect the database, logs, and agent credentials. Field-level classification/redaction, retention policies, encryption at rest, and richer credential storage remain future work.

## Explicit non-goals

v1 does not claim production analyst authentication, multi-tenancy, hostile-network deployment, immutable auditing, autonomous remediation, arbitrary endpoint control, or safe execution of general operating-system changes.
