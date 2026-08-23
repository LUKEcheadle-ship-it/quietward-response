# QuietWard Response v1.2.0-alpha.1 release checklist

Candidate branch: `feature/response-v12-hardening`

Backend/API version: `1.2.0a1`

This checklist separates development completion from qualification and publication. **Unchecked required items block release.**

## Candidate record

- [ ] Record the final candidate SHA after qualification-driven fixes are complete.
- [ ] Confirm branch is `feature/response-v12-hardening` and is not behind `main`.
- [ ] Confirm tracked checkout is clean.
- [ ] Confirm backend reports `1.2.0a1`.
- [ ] Confirm README, CHANGELOG, release notes, threat model, acceptance doc, release-correction record, reviewer guide and marketing kit describe the same v1.2 surface.

## Review package

- [x] `docs/V12_REVIEW_GUIDE.md` exists.
- [x] `docs/V12_MARKETING_KIT.md` exists.
- [x] `docs/V12_RELEASE_CORRECTIONS.md` exists.
- [x] `docs/V12_ALPHA_THREAT_MODEL.md` exists.
- [x] `docs/V12_ADVERSARIAL_REGRESSION_MATRIX.md` exists.
- [x] `docs/V12_ALPHA_ACCEPTANCE.md` exists.
- [x] versioned release notes exist at `docs/releases/v1.2.0-alpha.1.md`.
- [ ] Security/code review completed against the exact release SHA after the review corrections.
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
- [ ] Release-correction static/source gate.
- [ ] Fresh Alembic migration to `0003_agent_caps`.
- [ ] Historical Phase 1 → v1.2 migration/backfill qualification.
- [ ] `npm ci`.
- [ ] frontend typecheck.
- [ ] frontend production build.
- [ ] high-severity npm audit.
- [ ] public quick-start smoke and cleanup.
- [ ] capability-aware live process/file containment acceptance.
- [ ] Linux live privacy-preserving network diagnostic acceptance.
- [ ] live read-only QuietWard SQLite → authenticated Response incident acceptance.
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
- [ ] Generic `process_start` does **not** enable process termination without high-signal high/critical evidence.
- [ ] Generic `file_change` does **not** enable quarantine without qualified malware/known-bad evidence.
- [ ] Same-category-only events do not merge incidents without a concrete shared indicator or compatible high-signal attack stage.
- [ ] No generic shell/PowerShell/cmd/bash/script action exists.
- [ ] No raw PID/path/network-target action shape exists.

## Agent/key/continuous-runtime review

- [ ] Enrollment sends the initial signed capability report.
- [ ] Official poll path refreshes capabilities before every poll.
- [ ] Normal `poll_response_agent.py` mode is continuous; `--once` is qualification-only.
- [ ] bounded backoff and SIGTERM/SIGINT shutdown operate correctly.
- [ ] Linux user service installs and remains active under the normal user.
- [ ] Windows startup task is current-user and `RunLevel Limited`.
- [ ] Runtime config loader rejects symlinked/non-private POSIX credential files.
- [ ] Linux process termination is not advertised when pidfd support is unavailable.
- [ ] Two-phase key rotation prepare/activate works.
- [ ] Old active key is rejected immediately after activation.
- [ ] `--recover-next` recovers an interrupted staged rotation using the new credential.
- [ ] Normal agent listings/audit details do not expose secret material.
- [ ] Agent config/staged credential/network privacy key are not tracked in Git.
- [ ] Remote/non-loopback agent URL requires HTTPS.

## QuietWard adapter review

The adapter is part of Response and must not change the public QuietWard product.

- [ ] `forward_quietward_events.py` opens the detector database with SQLite `mode=ro` and `PRAGMA query_only=ON`.
- [ ] adapter does not import the QuietWard Python package.
- [ ] adapter does not execute INSERT/UPDATE/DELETE against QuietWard tables.
- [ ] host mismatch fails closed.
- [ ] QuietWard event IDs map deterministically to retry-safe Response UUIDs.
- [ ] stored QuietWard assessment severity is preserved.
- [ ] adapter requests use `source=quietward` and normal Response agent HMAC authentication.
- [ ] adapter cursor advances only after accepted/already-durable duplicate delivery.
- [ ] live qualification proves QuietWard database bytes do not change.
- [ ] Linux and Windows adapter startup paths remain user-scoped; Windows task is limited.

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
- [ ] per-file limit remains 64 MiB.
- [ ] total diagnostic hashing budget is capped at 256 MiB with explicit truncation/byte counters.
- [ ] source content/identity substitution is detected.
- [ ] quarantine requires only the opaque handle.
- [ ] quarantine/restore registry support is Linux/Windows only in v1.2.
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
- [ ] health endpoint reports `typed_controlled_response_v12`, not the retired demo-only scope.

## Marketing/claim review

Before announcement:

- [ ] marketing language identifies the product as an **experimental alpha**.
- [ ] no enterprise SOAR/EDR replacement claim.
- [ ] no autonomous remediation claim.
- [ ] no claim of immutable/WORM audit storage.
- [ ] no claim that unavailable firewall/identity/persistence/container/package actions exist.
- [ ] combined QuietWard/Response wording states that the bridge is Response-owned and reads QuietWard state read-only.
- [ ] no claim that every QuietWard finding automatically results in containment.
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
