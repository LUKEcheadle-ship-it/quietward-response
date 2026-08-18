# Roadmap

## Phase 1 — investigation foundation

Versioned ingestion, host tracking, deterministic correlation, incidents, timelines, rule-based recommendations, audit records, demo data, tests, and a read-oriented analyst console.

## Recommended Phase 2 — controlled response

1. Add OIDC authentication and role-based access for viewer, analyst, approver, and administrator roles.
2. Authenticate sensors with rotatable identities and signed, replay-resistant event envelopes.
3. Define a separate versioned action/result protocol with a small allow-list of typed operations.
4. Implement policy evaluation, risk classification, expiry, idempotency, and two-person approval.
5. Start with a reversible, low-risk action in a sandbox agent; never add a raw shell action.
6. Add tamper-evident audit hash chaining and export to immutable external storage.
7. Add PostgreSQL migrations, queues, rate limits, observability, retention, and backup/restore testing.

Automatic isolation, deletion, quarantine, firewall changes, and process termination remain out of scope until authorization, rollback, and safety controls are independently reviewed.
