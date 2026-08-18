# QuietWard Response v1 acceptance

QuietWard Response v1 is release-ready only after the Response and companion QuietWard branches pass both deterministic verification and the live two-repository loop.

## Automated deterministic gate

From the QuietWard Response checkout:

```bash
python scripts/verify_v1.py --quietward-repo ../quietward
```

This gate checks:

1. Python compilation for the Response backend/tests.
2. The full Response backend test suite with warnings treated as errors.
3. The executable server action registry contains exactly the one v1 demo action.
4. Alembic reaches `0002_phase2` from a fresh SQLite database.
5. Alembic upgrades a legacy Phase 1-shaped audit database and adds the Phase 2 schema.
6. Frontend TypeScript checks and production build.
7. npm dependency audit unless explicitly skipped for an offline machine.
8. The full companion QuietWard test suite when `--quietward-repo` is supplied.

## Automated live two-repository gate

```bash
python scripts/verify_v1_live.py --quietward-repo ../quietward
```

The live gate starts an isolated local Response API on a temporary database and then uses the actual QuietWard response client over HTTP. It proves:

1. one QuietWard agent can enroll;
2. a real HMAC-signed QuietWard event is accepted;
3. that event becomes an incident;
4. the controlled recommendation is produced;
5. an action starts in `pending` and therefore requires analyst approval;
6. deterministic policy allows the approved demo action;
7. QuietWard polls outward for the action;
8. the dedicated fixture changes exactly once;
9. a signed terminal result returns to Response;
10. a second poll does not re-execute the action; and
11. the complete audit chain verifies after the lifecycle.

## Manual UI smoke check

After the automated gates pass, start the normal stack and verify that Overview, Incidents, Agents, Hosts, and Events render without browser console errors. On the live-demo incident, confirm that the Response Actions card displays the transition from awaiting approval through succeeded and exposes the structured result.

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
