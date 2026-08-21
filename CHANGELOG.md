# Changelog

All notable changes to QuietWard Response are documented here.

## 1.2.0-alpha.1 — candidate 2026-08-21

First handle-bound containment alpha candidate.

### Added

- bounded `collect_host_diagnostic`, `collect_process_diagnostic`, and `collect_file_diagnostic` Response-agent actions
- short-lived opaque `qwrh1_...` local resource handles
- incident-bound handle provenance so a handle cannot be moved between incidents, hosts, or agents
- opt-in `terminate_process_by_handle` on Windows/Linux
- opt-in managed-root `quarantine_artifact_by_handle`
- `restore_quarantined_artifact_by_handle` rollback using a separate rollback handle
- local resource fingerprint/stale-target revalidation immediately before mutation
- disposable process/file containment qualification tests
- action-specific TTL ceilings; process termination and quarantine approvals are capped below resource-handle expiry
- API request-size and per-client rate limits
- hashed analyst bearer credentials with viewer/responder/admin RBAC outside loopback development
- authenticated analyst identity binding for audit records; `X-Actor-ID` cannot override a bearer identity
- session-only browser bearer-token support
- one-time analyst token/hash generator
- v1.2 static/local, live containment, and exact-branch finalization gates

### Hardened

- raw PID and filesystem-path targeting remains impossible through the action API
- generic shell/PowerShell/cmd/script execution remains absent
- process handles bind more than PID and protect agent/parent/critical OS processes
- file actions are limited to configured regular-file roots; symbolic links are excluded
- quarantine directory must be outside managed roots
- quarantine/restore has consumption receipts, deterministic rollback handles, stale-file checks, occupied-target checks, and interrupted-recovery validation
- interrupted process termination fails closed when the final outcome is indeterminate or a PID has been replaced
- pre-v1.2 incidents cannot gain new executable actions retroactively unless their persisted recommendation set authorizes them
- remote/non-development Response refuses startup without analyst credentials
- machine enrollment/HMAC/event routes remain separate from human analyst authentication
- CORS/security headers remain present on analyst 401/403 responses

### Still intentionally unavailable

- generic command execution
- raw PID/path action targets
- firewall/network-rule modification and host isolation
- persistence mutation
- account/session mutation
- container stop/remove
- service/package/configuration mutation
- autonomous remediation or LLM-generated executable commands

## 1.1.0-alpha.1 — candidate 2026-08-20

Broad incident-response planning alpha. Added the standalone deterministic Response Plan API, response families for malware/file, process/privilege, identity/authentication, persistence, network, container, vulnerability/configuration, evidence integrity, and operational incidents; sensor-neutral vendor vocabulary mapping; Response Plan UI; bounded ActionResult/evidence payloads; and a standalone outward-polling Response-owned demo agent. Endpoint execution remained demo-only in this release line.

Historical acceptance: `docs/V11_ALPHA_ACCEPTANCE.md` and `docs/releases/v1.1.0-alpha.1.md`.

## 1.0.0 — 2026-08-19

First end-to-end controlled-response release. Added versioned sensor-neutral event ingestion, deterministic correlation/timelines/recommendations, HMAC-authenticated agents and replay protection, typed action/result protocol, human approval and deterministic policy, outward polling, one demo-fixture action, durable idempotency, agent revocation, tamper-evident audit verification, analyst UI, PostgreSQL-ready migrations/Compose, and reproducible release gates.

The v1 safety boundary prohibited generic shell/PowerShell/cmd/bash, arbitrary process/service/file/firewall/host-isolation actions, and autonomous remediation.

Historical acceptance: `docs/V1_ACCEPTANCE.md`.
