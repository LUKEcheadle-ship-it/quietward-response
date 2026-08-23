# Changelog

All notable changes to QuietWard Response are documented here.

## 1.2.0-alpha.1 — candidate 2026-08-23

First handle-bound containment and bounded network-investigation alpha candidate.

### Added

- bounded `collect_host_diagnostic`, `collect_process_diagnostic`, `collect_file_diagnostic`, and Linux-only `collect_network_diagnostic` actions
- network diagnostics sourced directly from bounded `/proc/net` tables with no shell/subprocess path, no raw network address returned, at most 256 public rows, hashed remote identity, and short-lived opaque local socket handles
- short-lived incident-bound `qwrh1_...` resource handles
- opt-in exact-process termination on Windows/Linux
- opt-in managed-root file quarantine and separate rollback-handle restore
- signed agent capability reports with finite supported/enabled action sets, 15-minute freshness, `qwrh1` protocol attestation, and explicit `arbitrary_command_execution=false`
- endpoint capability visibility in the Agents UI and capability-aware action targeting in the incident console
- two-phase, crash-recoverable Response-agent HMAC key rotation with immediate old-key revocation after activation
- hashed analyst bearer credentials with viewer/responder/admin RBAC outside loopback development
- API request-size and per-client rate limits
- central credential-like field redaction before event/action/note persistence
- independently signed audit checkpoints that can be retained outside the Response database
- optional trusted-checkpoint startup verification
- v1.2-specific fresh and Phase 1→v1.2 migration qualification
- v1.2 static/local, capability-aware live containment, Linux network live acceptance, and exact-branch finalization gates

### Hardened

- action registry is an explicit eight-action finite surface and every action requires approval
- raw PID, raw filesystem path, raw network target, and generic shell/PowerShell/cmd/script execution remain impossible through the action API
- process/file mutating actions require agent-issued local resource identity rather than control-plane host identifiers
- normal UI no longer exposes free-form opaque-handle entry for containment
- normal UI offers non-demo actions only on affected agents that recently signed the exact capability as enabled
- process handles bind identity beyond PID and protect self/parent/critical OS processes
- Linux process termination uses pidfd-bound signaling where qualified and verifies target exit
- file identity includes SHA-256 content and filesystem metadata, revalidated before and after quarantine/restore
- symlinks are excluded; quarantine storage must remain outside managed roots
- consumed-handle replay returns only matching stored receipts
- pre-v1.2 incidents cannot retroactively gain executable v1.2 actions unless their persisted recommendation set authorizes them
- integrity/tamper incidents freeze medium/high/critical state-changing actions until endpoint evidence trust is restored
- stale/missing/disabled endpoint capabilities fail policy before dispatch
- agent disable clears endpoint trust/capability state and cancels undispatched work
- rotation one-time secrets are omitted from normal listings/audit details and are not printed by official helpers
- retired HMAC key material is not persisted after activation
- remote/non-development Response refuses startup without analyst credentials, a non-default enrollment token, and an independent non-development audit-checkpoint secret
- externally retained signed checkpoints detect full historical chain recomputation and deletion of already-checkpointed history in addition to ordinary chain tamper
- release audits reject tracked credential/config/state artifacts and sensitive persistence regressions

### Still intentionally unavailable

- generic command execution
- raw PID/path/network-target action targets
- firewall/network-rule modification and host isolation
- persistence mutation
- account/session mutation
- container stop/remove
- general service/package/configuration mutation
- autonomous remediation or LLM-generated executable commands
- multi-worker shared rate limiting
- enterprise OIDC/SSO
- OS-backed agent secret storage
- immutable/WORM external audit storage

## 1.1.0-alpha.1 — candidate 2026-08-20

Broad incident-response planning alpha. Added the standalone Response Plan API, broad response families, sensor-neutral vendor vocabulary mapping, Response Plan UI, bounded ActionResult/evidence payloads, and a standalone outward-polling Response-owned demo agent. Endpoint execution remained demo-only in this release line.

Historical acceptance: `docs/V11_ALPHA_ACCEPTANCE.md` and `docs/releases/v1.1.0-alpha.1.md`.

## 1.0.0 — 2026-08-19

First end-to-end controlled-response release. Added versioned sensor-neutral event ingestion, deterministic correlation/timelines/recommendations, HMAC-authenticated agents and replay protection, typed action/result protocol, human approval and deterministic policy, outward polling, one demo-fixture action, durable idempotency, agent revocation, tamper-evident audit verification, analyst UI, PostgreSQL-ready migrations/Compose, and reproducible release gates.

The v1 safety boundary prohibited generic shell/PowerShell/cmd/bash, arbitrary process/service/file/firewall/host-isolation actions, and autonomous remediation.

Historical acceptance: `docs/V1_ACCEPTANCE.md` and `docs/releases/v1.0.0.md`.
