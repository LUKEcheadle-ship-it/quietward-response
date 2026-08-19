# Security policy

QuietWard Response is pre-release security software. The v1 release candidate is designed for local or explicitly trusted-network incident investigation and controlled-response testing; it is not an Internet-facing production service.

## Reporting a vulnerability

Please use GitHub's private **Report a vulnerability** / Security Advisories workflow for this repository. Do not open a public issue containing exploit details, credentials, private event data, or host evidence.

Include the affected revision, a minimal reproduction, impact, and any suggested mitigation. Synthetic evidence is preferred.

## v1 security boundary

- The API defaults to `127.0.0.1` and CORS permits only configured origins.
- Event envelopes are strictly validated and duplicate UUIDs are idempotent/audited.
- QuietWard events are authenticated with enrolled per-agent HMAC credentials by default. Disabling this authentication is permitted only for loopback development.
- Unauthenticated generic/synthetic sensor sources are development-only and fail closed outside development.
- Signed agent requests bind method, target, timestamp, nonce, and exact body digest; persisted nonces provide replay resistance.
- Valid authenticated nonces are committed before later business validation so a rejected signed request cannot replay the same nonce.
- Database access uses SQLAlchemy parameter binding and Alembic migrations.
- Local SQLite data and QuietWard response-state files use private-file permissions where the operating system supports POSIX modes.
- Response actions are separately versioned, typed, allowlisted, approval-gated, policy-checked, and revalidated by QuietWard.
- Executable action creation is additionally bound to an enabled controlled recommendation on the specific incident, and policy rechecks that binding before dispatch.
- Only active incident states (`new`, `investigating`, or `contained`) can create or dispatch response actions; `resolved` and `dismissed` incidents fail closed.
- Pending, approved, and pre-execution `dispatching` actions are revoked when their target agent is disabled or their incident is resolved/dismissed. Once an endpoint has acknowledged `executing`, recovery/results remain available for audit correctness.
- Analyst identity headers are bounded before persistence; v1 still treats analyst identity itself as local-development grade rather than production RBAC.
- Agent polling is outbound from QuietWard; no inbound endpoint command listener is introduced.
- The only executable v1 action is `restart_quietward_demo_service`. It accepts no parameters and modifies only the dedicated QuietWard JSON demo fixture; it does not control a real service.
- QuietWard fails closed on unreadable/corrupt response outbox, action-ledger, or demo-fixture state and a full bounded outbox does not silently discard older queued evidence.
- There is no generic shell, PowerShell, cmd, bash, arbitrary process termination, arbitrary service control, firewall modification, file deletion/quarantine, or host isolation capability.
- Audit records are hash-chained and verifiable for tamper evidence. This is not equivalent to immutable external retention.
- The known development enrollment token is allowed only on a loopback development bind. Any non-loopback bind must use a replacement token, and wildcard CORS is rejected on non-loopback binds.
- v1 is intentionally single-process/single-worker; multiple API workers are unsupported until audit-chain append coordination moves into an atomic database mechanism.

## Deployment limitations

v1 does not provide production analyst authentication/RBAC, TLS termination, multi-tenancy, distributed replay storage, secret rotation automation, external immutable auditing, or general host remediation. Use TLS for any non-loopback transport and protect agent credentials as secrets.

See `docs/threat-model.md` for the detailed trust model and `docs/V1_ACCEPTANCE.md` for the required release gates.
