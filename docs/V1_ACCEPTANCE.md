# QuietWard Response v1 acceptance

QuietWard Response v1 is considered release-ready only after the Phase 1 and Phase 2 branches have been validated together with the companion QuietWard integration branch.

## Required validation

1. Apply Alembic through `0002_phase2` on a fresh database and an upgraded Phase 1 database.
2. Run the full backend test suite with warnings treated as errors.
3. Run frontend TypeScript checks, production build, and dependency audit.
4. Enroll one real QuietWard endpoint with a non-default enrollment token.
5. Verify an authenticated QuietWard event is accepted and an unsigned or replayed event is rejected.
6. Run the controlled demo fixture end to end: unhealthy fixture -> incident -> prepared action -> analyst approval -> agent poll -> single execution -> signed result.
7. Run the same poll again and confirm the action is not executed a second time.
8. Verify `/api/v1/audit/verify` reports a valid chain after the full lifecycle.
9. Confirm QuietWard continues local monitoring when Response is disabled and when Response is temporarily unreachable.
10. Confirm no generic command, process-control, filesystem-deletion, firewall, quarantine, or host-isolation action exists in either action registry.

## Release boundary

v1 deliberately includes only one executable response action, `restart_quietward_demo_service`, and that action changes only the dedicated QuietWard-owned JSON demo fixture. It is not an operating-system service restart.

The v1 safety model is:

`observe -> recommend -> human approve -> deterministic policy -> endpoint allowlist -> act -> signed result -> audit`

Anything that controls arbitrary host state belongs to a later version and must preserve this approval/policy/endpoint-validation boundary.

## Known v1 limitations

- Analyst identity is local-development grade rather than OIDC/RBAC.
- HMAC transport assumes TLS outside loopback or a trusted local network.
- The audit chain is tamper-evident, not immutable.
- No multi-tenant or cloud deployment model is claimed.
- No autonomous remediation is enabled.
