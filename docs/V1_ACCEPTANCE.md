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
4. Executable action creation is rejected unless the action is an enabled controlled recommendation on that specific incident, and policy rechecks the same binding before dispatch.
5. Alembic reaches `0002_phase2` from a fresh SQLite database.
6. `alembic check` confirms current ORM metadata has no migration drift beyond the frozen v1 revisions.
7. A real database created from the frozen `0001_phase1` migration upgrades to v1 and its legacy unhashed audit row is backfilled/verified exactly once.
8. Frontend TypeScript checks and production build.
9. npm dependency audit unless explicitly skipped for an offline machine.
10. The full companion QuietWard test suite when `--quietward-repo` is supplied.

## Automated live two-repository gate

```bash
python scripts/verify_v1_live.py --quietward-repo ../quietward
```

The live gate starts an isolated local Response API on a temporary database and then uses the actual QuietWard response client over HTTP. It proves:

1. one QuietWard agent can enroll;
2. a real HMAC-signed QuietWard event is accepted;
3. that event becomes an incident;
4. the controlled recommendation metadata survives the API response and is shown as executable only for the demo fixture;
5. an action starts in `pending` and therefore requires analyst approval;
6. deterministic policy allows the approved incident-bound demo action;
7. QuietWard polls outward for the action;
8. the dedicated fixture changes exactly once;
9. a signed terminal result returns to Response;
10. a second poll does not re-execute the action; and
11. the complete audit chain verifies after the lifecycle.

## Manual UI smoke check

After the automated gates pass, start the normal stack and verify that Overview, Incidents, Agents, Hosts, and Events render without browser console errors. On the live-demo incident, confirm that the Response Actions card displays the transition from awaiting approval through succeeded and exposes the structured result.

## Supported v1 runtime shape

v1 intentionally uses **one Response API process/worker**. Request transactions are serialized inside that process so concurrent HTTP operations cannot independently append from the same audit-chain head. Both the native launcher and backend container explicitly start Uvicorn with `--workers 1`.

Do not horizontally scale the v1 API or start multiple independent API workers against one database. A future multi-worker release must replace the process-local serialization guard with a database-backed atomic audit append/head mechanism and requalify replay/action concurrency.

## Release boundary

v1 deliberately includes only one executable response action, `restart_quietward_demo_service`, and that action changes only the dedicated QuietWard-owned JSON demo fixture. It is not an operating-system service restart.

The v1 safety model is:

`observe -> recommend -> human approve -> deterministic policy -> endpoint allowlist -> act -> signed result -> audit`

Anything that controls arbitrary host state belongs to a later version and must preserve this approval/policy/endpoint-validation boundary.

## Known v1 limitations

- Analyst identity is local-development grade rather than OIDC/RBAC.
- HMAC transport assumes TLS outside loopback or a trusted local network.
- The audit chain is tamper-evident, not immutable.
- The API is qualified only as a single-process/single-worker service.
- No multi-tenant, horizontally scaled, or cloud deployment model is claimed.
- No autonomous remediation is enabled.
