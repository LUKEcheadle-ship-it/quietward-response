# Roadmap

## Phase 1 — foundation

- Versioned event protocol and strict ingestion
- Host inventory and persistent event store
- Explainable deterministic correlation
- Incident timelines and rule-based cause assessment
- Diagnostic versus disabled remediation recommendations
- Structured audit trail
- Local dark-mode investigation UI and synthetic demos

## Recommended Phase 2 — controlled response

1. Authenticated sensor enrollment with per-agent keys, rotation, revocation, signed envelopes, sequence numbers, and replay windows.
2. Analyst authentication, role-based access, incident ownership, and two-person approval for high-impact actions.
3. A separately versioned, allowlisted action protocol. It must never accept arbitrary shell text.
4. A dedicated action broker isolated from the investigation API, using scoped and expiring capabilities.
5. Dry-run previews, target verification, precondition checks, bounded timeouts, rollback metadata, and endpoint refusal rules.
6. Cryptographic audit chaining, signed checkpoints, immutable retention export, and verification tooling.
7. PostgreSQL production migrations, backup/restore tests, rate limits, retention policy, and encrypted evidence fields.
8. Cross-sensor correlation, source trust scoring, and authenticated QuietWard protocol implementation in a separate QuietWard change.

Host isolation, process termination, firewall changes, file quarantine/deletion, and service changes remain prohibited until these controls are implemented and independently tested.
