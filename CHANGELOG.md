# Changelog

All notable changes to QuietWard Response are documented here.

## 1.0.0-rc.1 — 2026-08-18

Release-candidate implementation of the first end-to-end controlled-response system.

### Added

- versioned sensor-neutral event protocol
- deterministic host/event correlation into explainable incidents
- incident timelines, cause assessment, and rule-based recommendations
- authenticated QuietWard agent enrollment
- HMAC-SHA256 signed QuietWard events, polling, and action results
- persisted nonce replay protection and host binding
- typed, separately versioned ActionRequest / ActionResult protocol
- explicit analyst approval and deterministic action policy
- agent-initiated action polling
- one executable allowlisted demo-fixture action with no arbitrary parameters
- endpoint retry/crash idempotency and duplicate terminal-result checks
- agent disable/re-enable API and console control
- tamper-evident hash-chained audit verification
- Agents and Response Actions analyst UI
- PostgreSQL-ready Alembic schema and Docker Compose path
- deterministic v1 release gate and real two-repository HTTP acceptance harness

### Hardened

- frozen Alembic revisions instead of importing mutable current ORM metadata
- consistent runtime/migration `.env` database selection
- combined launcher honors repository `.env` API-port selection
- non-development rejection of the known development enrollment token
- non-development enforcement of QuietWard agent authentication
- non-development rejection of unauthenticated generic sensor sources
- single-use authenticated nonces even when later business validation rejects the request
- bounded analyst identity headers before database persistence
- private local SQLite and endpoint integration state files where POSIX modes are supported
- request serialization for single-process v1 audit-chain consistency
- QuietWard `info` severity compatibility normalization to canonical `informational`
- controlled recommendation metadata preserved through FastAPI response serialization
- dedicated demo incidents keep their recommendation set focused on the demo fixture rather than unrelated operational/disk guidance

### Safety boundary

v1 has no generic shell, PowerShell, cmd, bash, arbitrary process termination, arbitrary service control, file deletion/quarantine, firewall modification, host isolation, or autonomous remediation. The only executable action changes a dedicated JSON demo fixture after human approval, deterministic policy validation, and endpoint-side allowlist validation.

### Release gate

This revision remains a release candidate until both commands pass on a real checkout:

```bash
python scripts/verify_v1.py --quietward-repo ../quietward
python scripts/verify_v1_live.py --quietward-repo ../quietward
```

After those gates and the documented UI smoke check pass, promote the backend version from `1.0.0rc1` to `1.0.0` and merge the staged PRs.
