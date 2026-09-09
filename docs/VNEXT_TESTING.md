# QuietWard + Response vNext testing

The Guided Incident Response vNext branch is intentionally split into two qualification concepts:

1. **Current implemented slice** — everything already built must pass its tests.
2. **Final combined release coverage** — every QuietWard finding family must have a tested Response resolution path before release.

The second gate is expected to remain blocked while remediation families are still being implemented.

## Required branches

Use the paired feature branches in separate local checkouts:

- QuietWard: `feature/guided-incident-response-vnext`
- QuietWard Response: `feature/guided-incident-response-vnext`

The one-command harness refuses mixed branches or tracked working-tree changes so the recorded HEAD SHAs match the code actually being tested.

## One-command current-slice qualification

From the `quietward-response` checkout:

```bash
python scripts/verify_vnext_current_slice.py --quietward-repo ../quietward
```

On Windows, if `python` does not resolve to Python 3.12+:

```powershell
py -3.12 scripts\verify_vnext_current_slice.py --quietward-repo ..\quietward
```

The wrapper runs:

- exact paired feature-branch and clean tracked-tree checks
- Response Python compile checks
- public-release audit
- complete Response backend pytest suite with warnings treated as errors
- exact typed action-surface verification
- fresh and upgrade migration checks plus Alembic drift check
- frontend clean install, typecheck, production build, and npm high-severity audit
- public quick-start smoke test
- complete companion QuietWard compile/audit/unit-test suite
- focused QuietWard Response handoff verification
- live QuietWard -> Response joint acceptance
- live disposable-process evidence-bound containment verification
- stale process-handle fail-closed verification
- Response verifier/self-process protection verification
- final resolution-coverage status report

A successful current-slice run ends with:

```text
VNEXT CURRENT IMPLEMENTED SLICE: PASS
```

and prints the exact QuietWard and Response HEAD SHAs that were qualified.

The final resolution-coverage report may still say `BLOCKED`; that is expected until every remediation family is complete.

## Live containment safety

`scripts/verify_vnext_process_containment.py` creates its own disposable Python child process, records an endpoint-local opaque evidence handle for that process, terminates only that evidence-bound child, and confirms the original process instance exited.

The test does not accept a PID or command from the user. It also verifies that:

- a stale process handle fails closed after its process exits
- the Response verification process itself is protected
- arbitrary PID targeting is not exposed
- arbitrary command execution is not exposed

If the disposable child cannot be observed in the bounded process inventory, the test fails rather than falling back to a broader process-control mechanism.

## Final combined release gate

The final combined release must also pass:

```bash
python scripts/verify_vnext_resolution_coverage.py
```

This command intentionally returns a failure while any QuietWard response category remains unresolved or unqualified. Do not make the PRs ready for review or merge the combined update merely because the current-slice qualification passes.

## Development-only offline option

If npm audit cannot be reached during a local development check:

```bash
python scripts/verify_vnext_current_slice.py --quietward-repo ../quietward --skip-npm-audit
```

A run using `--skip-npm-audit` is not release qualification.
