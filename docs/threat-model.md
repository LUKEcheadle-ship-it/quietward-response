# Threat model

## Assets and trust boundaries

Protected assets include event integrity, incident state, analyst decisions, audit history, source credentials, and any future action authorization. Sensor payloads cross an untrusted boundary before validation. The browser, API, database, and future endpoint action channel are separate trust zones.

Phase 1 is local-development software. Binding it publicly or placing it behind an untrusted reverse proxy is outside the supported boundary.

## Threats and current controls

### Forged events

An attacker could submit fabricated high-severity evidence. Phase 1 strictly validates a versioned schema, records source identity as claimed data, normalizes values, and audits acceptance. This limits parser abuse but does not authenticate a sensor. Signed enrollment and per-agent credentials are required in Phase 2.

### Compromised endpoint agent

A valid agent could lie, omit evidence, or flood the service. Deterministic correlation is explainable and preserves originals, but cannot prove a compromised source truthful. Phase 2 should add rate limits, source health, cross-sensor corroboration, revocation, and confidence adjustment.

### Replay attacks

Accepted event UUIDs are globally idempotent; duplicates return `409` and produce an audit record. UUID uniqueness alone does not prevent replay with a new ID. Phase 2 requires signed envelopes containing source sequence numbers, nonces, and bounded timestamp skew.

### Malicious response requests

Phase 1 exposes no endpoint-action, shell, file, firewall, isolation, quarantine, or process-control API. Remediation recommendations are disabled records. Future requests require a separate allowlisted action protocol, policy evaluation, scoped capability tokens, human approval, expiry, and endpoint-side validation.

### API compromise

Safe defaults include loopback binding, narrow CORS, strict Pydantic envelopes, parameterized SQLAlchemy queries, no raw shell surface, and environment-only secrets. Phase 2 must add authenticated TLS, RBAC, CSRF strategy where applicable, rate limits, security headers, secret rotation, and deployment hardening.

### Audit-log tampering

Application code appends audit rows and never exposes deletion/update endpoints, but a database administrator can still alter Phase 1 records. Phase 2 should hash-chain records, sign periodic checkpoints, export to write-once retention, and continuously verify the chain.

### Privilege escalation

The Phase 1 server needs no endpoint privileges and should run as an unprivileged account. Containers do not mount the host filesystem or runtime socket. A future action broker must be isolated from the investigation API and grant only narrowly defined, expiring capabilities.

### Data leakage

Events may contain sensitive operational evidence. Phase 1 stores accepted fields as submitted, so deployments must use synthetic/non-sensitive data unless local database access is adequately protected. Future work should add field classification, redaction policy, retention limits, encryption, and access auditing.

## Explicit non-goals

Phase 1 does not claim production authentication, multi-tenancy, hostile-network deployment, cryptographic audit immutability, or safe automated remediation.
