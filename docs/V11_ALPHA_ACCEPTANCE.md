# QuietWard Response v1.1.0-alpha.1 acceptance

This document defines the release boundary for the first expanded diagnostic-response alpha.

## Release identifier

- GitHub release/tag: `v1.1.0-alpha.1`
- backend/API version: `1.1.0a1`
- Response branch: `feature/response-diagnostic-expansion`
- QuietWard branch: `feature/response-diagnostic-expansion`

This alpha does not replace the released `v1.0.0` qualification record.

## What the alpha adds

The released v1 demo-fixture action remains unchanged. The alpha adds eight approval-gated, parameter-free, read-only diagnostic response actions:

- `collect_process_diagnostic`
- `collect_network_diagnostic`
- `collect_persistence_diagnostic`
- `collect_file_diagnostic`
- `collect_container_diagnostic`
- `collect_identity_diagnostic`
- `collect_vulnerability_diagnostic`
- `collect_integrity_diagnostic`

Each diagnostic returns only bounded evidence already observed by QuietWard on the enrolled host. The endpoint does not accept an arbitrary path, PID, service name, IP address, container ID, command, script, or shell fragment from Response.

## QuietWard detection expansion included with this alpha candidate

The companion QuietWard branch adds:

- cross-subject, same-host multi-stage attack-chain correlation inside a bounded 15-minute window;
- stronger deterministic priority for large authentication-failure bursts;
- credential-spray-aware scoring when a detector provides distinct-user counts;
- additional weighting for already-produced high-confidence behavior markers such as encoded shell chains, downloader/execute chains, encoded commands, living-off-the-land patterns, cryptominer indicators, and dangerous container configuration markers;
- unchanged observation-only local analysis: QuietWard detection still executes no general host remediation by itself.

## Automated gate

Run from the Response checkout with the matching QuietWard checkout beside it:

```text
python scripts/finalize_v11_alpha.py --quietward-repo ../quietward
```

The wrapper requires both local branches to match their exact pushed GitHub feature branches and to contain current `origin/main`.

It runs:

1. `scripts/verify_v11_alpha.py`
   - Response compile checks
   - public-release audit
   - full backend pytest suite with warnings as errors
   - exact v1.1 diagnostic action-surface check
   - fresh Alembic migration
   - Phase-1-to-current migration
   - Alembic drift check
   - frontend `npm ci`
   - frontend typecheck
   - frontend production build
   - high-severity npm audit
   - public quick-start startup and cleanup smoke
   - companion QuietWard compile check
   - QuietWard public-release audit
   - complete QuietWard unittest suite, including expanded detection tests

2. `scripts/verify_v1_live.py`
   - proves the released authenticated demo-fixture lifecycle still works end to end and exactly once.

3. `scripts/verify_v11_alpha_live.py`
   - creates a test-owned QuietWard malware-signature event
   - sends it over the real HMAC-authenticated event path
   - proves Response creates an incident with the file diagnostic recommendation
   - proves the diagnostic requires explicit analyst approval and deterministic policy allowance
   - proves the endpoint polls outward and independently validates the typed action
   - proves the returned diagnostic is read-only and reports `system_state_changed=false`
   - proves the triggering QuietWard event is present in the bounded result
   - proves the signed terminal result is stored
   - proves terminal replay does not re-execute work
   - proves the Response audit chain still verifies

## Manual browser smoke before publication

After the automated wrapper passes:

1. start Response with the normal quick-start path;
2. create one local test incident that exposes a diagnostic response;
3. open the incident page;
4. confirm the diagnostic action is clearly labeled approval-required/read-only;
5. approve it once;
6. run the matching QuietWard cycle;
7. confirm the UI shows a succeeded result and bounded evidence without displaying any generic command input;
8. confirm the released demo-fixture workflow still appears and functions as before;
9. stop both services and confirm ports are released.

## Alpha safety boundary

The alpha still has no generic remote administration surface.

Not enabled:

- arbitrary shell / PowerShell / cmd / bash
- arbitrary process termination
- arbitrary service stop/restart
- arbitrary file deletion or quarantine
- arbitrary firewall rules
- host isolation
- arbitrary account lockout/session revocation
- arbitrary package installation/update
- autonomous remediation
- LLM-generated executable commands

The only system-state-changing endpoint action remains the dedicated v1 JSON demo fixture.

## Why higher-impact containment is not in this alpha

QuietWard deliberately redacts or hashes several sensitive endpoint identifiers before persistence, including raw usernames, remote addresses, and container IDs. That privacy boundary prevents Response from safely targeting those resources using a server-supplied string.

The next containment layer must use endpoint-created opaque resource handles with local precondition checks, expiry, rollback metadata, and resource-specific executors. That work should happen after this diagnostic alpha is qualified rather than weakening the current privacy model.

## Known limitations

- analyst identity remains development-grade `X-Actor-ID`, not OIDC/RBAC;
- HMAC transport still assumes TLS outside loopback/trusted development;
- audit history is tamper-evident, not immutable;
- API qualification remains single-process/single-worker;
- diagnostic results reflect bounded recent QuietWard evidence in the running endpoint process, not an unrestricted forensic collection engine;
- read-only diagnostics are approval-gated in this alpha for control-plane consistency, even though they do not change host state;
- higher-impact containment and remediation remain intentionally disabled.

## Publication rule

Do not publish/tag `v1.1.0-alpha.1` unless the complete automated wrapper and manual browser smoke both pass on the exact pushed candidate branches.
