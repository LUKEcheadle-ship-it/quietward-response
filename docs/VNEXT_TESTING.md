# QuietWard + Response vNext testing

The Guided Incident Response vNext branch is intentionally split into two qualification concepts:

1. **Current implemented slice** — everything already built must pass its tests.
2. **Final combined release coverage** — every QuietWard finding family must have a tested Response resolution path before release.

The second gate now executes the implemented human-recovery contracts for all 12 categories. It must pass with no missing or skipped category. This is evidence-attested operator recovery, not implementation of every automatic platform-specific remediation executor.

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

A current-slice PASS alone is not release clearance. The separate final resolution-coverage gate must also PASS, together with native and real-browser acceptance on the selected source.

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

This command runs the API and negative-path contract tests and returns failure if any category lacks a tested recovery or escalation path, or any required case fails or skips. It does not inspect real endpoint artifacts: the product explicitly labels outcome verification as independent human attestation. Do not make the PRs ready or merge merely because the current-slice qualification passes.

The browser acceptance is a separate executable gate:

```bash
python scripts/verify_guided_recovery_browser.py --output <new-evidence-directory>
```

It requires the built frontend and Playwright/Chromium. It uses separate named analyst sessions and disposable synthetic state to exercise approval, ordered checkpoints, independent verification, closure and acknowledged-but-unresolved escalation. No endpoint agent or action is started by this browser test.

## Development-only offline option

If npm audit cannot be reached during a local development check:

```bash
python scripts/verify_vnext_current_slice.py --quietward-repo ../quietward --skip-npm-audit
```

A run using `--skip-npm-audit` is not release qualification.
