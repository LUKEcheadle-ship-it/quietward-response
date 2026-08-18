# QuietWard Response v1 acceptance

QuietWard Response v1 is release-ready only after the Response and companion QuietWard branches pass deterministic verification, publication audits, the live two-repository loop, and the manual UI smoke check.

## Required release wrapper

From the QuietWard Response checkout, with the companion QuietWard integration checkout available:

```bash
python scripts/finalize_v1.py --quietward-repo ../quietward
```

Before running product tests, the wrapper verifies that:

- Response is on `feature/phase2-secure-integration`;
- QuietWard is on `feature/response-platform-integration`;
- each checkout has the expected `origin` repository;
- tracked working-tree changes are committed;
- `.env` is not tracked;
- current remote refs/tags are fetched;
- local HEAD exactly matches the corresponding pushed GitHub feature branch; and
- each release branch contains current `origin/main`.

This prevents qualifying stale, unpushed, or already-outdated source.

## Automated deterministic gate

The wrapper first runs:

```bash
python scripts/verify_v1.py --quietward-repo ../quietward
```

This gate checks:

1. A Python 3.12 venv exists and declared Response dependencies are reconciled.
2. Response backend/tests compile.
3. Response public-release audit passes, including tracked-file checks, high-confidence secret checks, selected private-machine-path checks, and reachable git-history checks for sensitive paths/tokens.
4. The full Response backend test suite passes with warnings treated as errors.
5. The executable server action registry contains exactly `restart_quietward_demo_service`.
6. Executable action creation is bound to an enabled controlled recommendation on the exact active incident, with policy rechecks before dispatch.
7. Agent revocation, incident closure, expiry, duplicate lifecycle prevention, replay protection, timestamp validation, result idempotency, action execution timing, and audit-chain behavior pass their regression coverage.
8. Alembic reaches `0002_phase2` from a fresh SQLite database.
9. `alembic check` confirms no ORM/migration drift beyond the frozen v1 revisions.
10. A genuine database created from `0001_phase1` upgrades to v1 and its legacy unhashed audit row is backfilled/verified exactly once.
11. Frontend dependencies are rebuilt from `package-lock.json` with `npm ci`.
12. Frontend TypeScript checks and production build pass.
13. npm audit passes at the high-severity threshold. The final release wrapper does not allow this audit to be skipped.
14. Companion QuietWard source/tests compile.
15. QuietWard's own public-release audit passes.
16. The full companion QuietWard unittest suite passes.

## Automated live two-repository gate

The wrapper then runs:

```bash
python scripts/verify_v1_live.py --quietward-repo ../quietward
```

The live gate starts an isolated local Response API on a temporary database and uses the actual QuietWard response client over HTTP. It proves:

1. one QuietWard agent can enroll;
2. a real HMAC-signed QuietWard event is accepted;
3. that event becomes an incident;
4. the controlled recommendation metadata survives the API response and is executable only for the dedicated demo fixture;
5. an action starts in `pending` and therefore requires analyst approval;
6. deterministic policy allows the approved incident-bound demo action;
7. QuietWard polls outward for the action;
8. the endpoint validates the typed action again before execution;
9. the dedicated fixture changes exactly once;
10. a signed terminal result returns to Response;
11. a second poll does not re-execute the action; and
12. the complete audit chain verifies after the lifecycle.

## Manual UI smoke check

After the automated gates pass, start the normal stack and verify that Overview, Incidents, Agents, Hosts, and Events render without browser console errors. On the live-demo incident, confirm that the Response Actions card displays the lifecycle from awaiting approval through succeeded, shows the selected target agent, and exposes the structured result.

Also verify that:

- a resolved/dismissed incident cannot prepare or approve a new action;
- an expired action is not shown as approvable;
- a disabled agent is not offered as an execution target; and
- backend policy/conflict errors are shown as useful messages rather than only HTTP status codes.

## Version promotion

The first clean acceptance run is performed while Response is still `1.0.0rc1`. After that run and the UI smoke check pass:

```bash
python scripts/promote_v1.py
```

The promotion helper deterministically updates the backend version, frontend package/package-lock version, demo source version, README release status, and changelog to `1.0.0`.

Review and commit/push those version-only changes, then rerun the **complete** `finalize_v1.py` wrapper and UI smoke check. Only the final `1.0.0` commit that passes again is eligible for merge, tag, repository-publication, or GitHub Release creation.

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
