# QuietWard Response v1.2.0-alpha.1 release checklist

Candidate branch: `feature/response-v12-hardening`

Backend/API version: `1.2.0a1`

This checklist separates development completion from qualification and publication. **Unchecked required items block release.**

## Candidate record

- [ ] Record the final candidate SHA after documentation/review-only changes are complete.
- [ ] Confirm branch is `feature/response-v12-hardening` and is not behind `main`.
- [ ] Confirm tracked checkout is clean.
- [ ] Confirm backend reports `1.2.0a1`.
- [ ] Confirm README, CHANGELOG, release notes, threat model, acceptance doc, reviewer guide and marketing kit describe the same v1.2 surface.

## Review package

- [x] `docs/V12_REVIEW_GUIDE.md` exists.
- [x] `docs/V12_MARKETING_KIT.md` exists.
- [x] `docs/V12_ALPHA_THREAT_MODEL.md` exists.
- [x] `docs/V12_ADVERSARIAL_REGRESSION_MATRIX.md` exists.
- [x] `docs/V12_ALPHA_ACCEPTANCE.md` exists.
- [x] versioned release notes exist at `docs/releases/v1.2.0-alpha.1.md`.
- [ ] Security/code review completed against the exact release SHA.
- [ ] Reviewer confirms no generic command/raw-target execution path exists.

## Automated finalizer

From an exact clean checkout run:

```text
python scripts/finalize_v12_alpha.py
```

Required PASS evidence:

- [ ] Python compile checks.
- [ ] Full backend pytest with warnings treated as errors.
- [ ] Public-release secret/history audit.
- [ ] Tracked sensitive-artifact audit.
- [ ] Durable sensitive-persistence scan.
- [ ] Exact eight-action surface verification.
- [ ] Fresh Alembic migration to `0003_agent_caps`.
- [ ] Historical Phase 1 → v1.2 migration/backfill qualification.
- [ ] `npm ci`.
- [ ] frontend typecheck.
- [ ] frontend production build.
- [ ] high-severity npm audit.
- [ ] public quick-start smoke and cleanup.
- [ ] capability-aware live process/file containment acceptance.
- [ ] Linux live privacy-preserving network diagnostic acceptance.
- [ ] final audit-chain verification and terminal replay checks.

Record finalizer output with the candidate SHA. Do not substitute existence of tests for execution evidence.

## Action/control-plane review

- [ ] Registry contains exactly the documented eight actions.
- [ ] Every registered action requires analyst approval.
- [ ] Policy rechecks incident/action/host/agent/OS/approval/expiry before dispatch.
- [ ] Non-demo actions require fresh signed exact-action agent capability state.
- [ ] Capability state older than 15 minutes or implausibly future dated fails closed.
- [ ] Disabling an agent clears capability and staged rotation trust.
- [ ] Integrity-compromise incidents block medium/high/critical state-changing actions.
- [ ] No generic shell/PowerShell/cmd/bash/script action exists.
- [ ] No raw PID/path/network-target action shape exists.

## Agent/key review

- [ ] Enrollment sends the initial signed capability report.
- [ ] Official poll path refreshes capabilities before polling.
- [ ] Two-phase key rotation prepare/activate works.
- [ ] Old active key is rejected immediately after activation.
- [ ] `--recover-next` recovers an interrupted staged rotation using the new credential.
- [ ] Normal agent listings/audit details do not expose secret material.
- [ ] Agent config/staged credential/network privacy key are not tracked in Git.
- [ ] Remote/non-loopback agent URL requires HTTPS.

## Process containment

Use only a test-owned disposable child process.

- [ ] diagnostic returns an opaque eligible handle.
- [ ] raw PID submission is rejected.
- [ ] stale/reused identity is rejected.
- [ ] protected/self/critical process safeguards pass.
- [ ] exact target exit is verified.
- [ ] terminal replay does not terminate again.

## Managed-file containment

Use only disposable files under a temporary managed root.

- [ ] diagnostic returns no absolute managed-file path.
- [ ] symlinks are not eligible.
- [ ] source content/identity substitution is detected.
- [ ] quarantine requires only the opaque handle.
- [ ] quarantine produces a rollback handle.
- [ ] occupied restore target fails closed.
- [ ] changed quarantine object fails closed.
- [ ] successful restore returns the original bytes.
- [ ] terminal replay does not apply the move again.

## Linux network diagnostic

- [ ] Linux-only action is advertised by the canonical v1.2 agent.
- [ ] action accepts no parameters.
- [ ] direct `/proc/net` parsing uses no shell/subprocess.
- [ ] result is capped at 256 rows with explicit truncation.
- [ ] no raw local/remote IP, UID or inode appears in Response results.
- [ ] endpoint-local HMAC-SHA256 remote pseudonyms are present for concrete remote addresses.
- [ ] privacy key remains only in the endpoint state directory.
- [ ] server-supplied network target is rejected.
- [ ] no firewall/host-isolation action exists.

## Analyst/browser smoke

Complete every item in `docs/V12_ALPHA_ACCEPTANCE.md` on the same SHA.

- [ ] Overview/Incidents/Hosts/Agents/Events render without console errors.
- [ ] capability freshness/enabled actions are visible.
- [ ] read-only vs state-changing actions are visually distinct.
- [ ] handle-based controls use trusted prior-result selectors rather than free-form target input.
- [ ] key rotation remains operational through the UI-visible agent state.
- [ ] viewer cannot mutate in production-mode browser test.
- [ ] clearing session token removes authenticated UI access.
- [ ] retained audit checkpoint remains valid after legitimate later activity.

## Marketing/claim review

Before announcement:

- [ ] marketing language identifies the product as an **experimental alpha**.
- [ ] no enterprise SOAR/EDR replacement claim.
- [ ] no autonomous remediation claim.
- [ ] no claim of immutable/WORM audit storage.
- [ ] no claim that unavailable firewall/identity/persistence/container/package actions exist.
- [ ] demo uses only synthetic telemetry, disposable process/file fixtures and safe network diagnostics.
- [ ] release announcement includes the exact qualified SHA.

Recommended source: `docs/V12_MARKETING_KIT.md`.

## Publication

Only after every required qualification item passes on the same SHA:

- [ ] mark the release PR ready for final review.
- [ ] merge to Response `main` with explicit owner authorization.
- [ ] create tag `v1.2.0-alpha.1`.
- [ ] publish release notes from `docs/releases/v1.2.0-alpha.1.md`.
- [ ] publish the reviewed launch copy.
- [ ] retain qualification evidence privately where it contains machine-specific information.

Any failed or unchecked required qualification item blocks release.
