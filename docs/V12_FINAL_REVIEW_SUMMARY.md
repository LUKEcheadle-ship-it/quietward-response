# QuietWard Response v1.2 final repository review

This record documents the repository-side release review for `v1.2.0-alpha.1`.
It does **not** substitute for the same-SHA native Linux, native Windows, installed-service/browser, and real-QuietWard execution gates in `docs/V12_ALPHA_ACCEPTANCE.md`.

## Reviewed release boundary

- exactly eight registered, typed, analyst-approval-gated actions;
- no generic shell, PowerShell, cmd, bash, script, raw PID, raw path, or raw network-target execution surface;
- deterministic policy revalidation before dispatch, including fail-closed missing-host handling, incident/recommendation binding, target agent/host/OS, capability freshness, approval, and expiry;
- endpoint-issued opaque process/file handles with stale-identity checks and exactly-once/replay receipts;
- Linux pidfd-bound and Windows creation-identity-bound disposable process containment paths;
- managed-root file quarantine/restore with SHA-256 identity, rollback handle, bounded hashing, and fail-closed occupied/tampered restore behavior;
- continuous outward-polling endpoint agent, signed capability reports, two-phase key rotation, and immediate old-key revocation;
- hardened private config/ledger/handle/cursor state using bounded no-follow reads and randomized exclusive atomic writes;
- viewer/responder/admin analyst RBAC outside loopback development;
- browser API configuration refuses remote plaintext HTTP so bearer tokens are not intentionally sent over an unapproved non-loopback HTTP boundary;
- Response-owned QuietWard adapter opens detector SQLite `mode=ro` with `PRAGMA query_only=ON` and uses an event-ingestion-only derived HMAC key;
- before signing/transmission, the adapter applies a strict outbound allowlist: raw listener/network addresses, absolute detector file subjects/paths, raw usernames/commands, arbitrary metadata, unknown attributes, and unreviewed top-level detector fields are dropped;
- current release tree forbids GitHub Actions workflows, runtime databases, credentials, staged agent secrets, private key files, and high-confidence secret artifacts;
- release/marketing language remains **experimental alpha** and does not claim autonomous remediation, enterprise EDR/SOAR replacement, immutable audit storage, breach prevention, or unavailable response actions.

## Remaining release evidence

Publication remains blocked until the exact frozen candidate SHA passes all documented gates:

1. native Linux: `python scripts/finalize_v12_alpha.py`;
2. native Windows, same SHA: `python scripts/verify_v12_windows_live.py`;
3. every installed-service/browser/real-QuietWard item in `docs/V12_ALPHA_ACCEPTANCE.md`;
4. actual released QuietWard `v0.5.0-alpha.1` bridge smoke proving the QuietWard database remains unchanged;
5. final public-release audit and release checklist evidence on that same SHA.

Any qualification-driven code change creates a new candidate SHA and requires the native/operational gates to be repeated.
