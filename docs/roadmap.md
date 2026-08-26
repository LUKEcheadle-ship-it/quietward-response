# Roadmap

## v1 — controlled response foundation

The v1 scope is intentionally narrow and testable:

- versioned event protocol and strict ingestion
- host inventory and persistent event store
- explainable deterministic correlation
- incident timelines and rule-based cause assessment
- authenticated QuietWard agent enrollment
- HMAC-signed events with timestamp/nonce replay protection
- separately versioned typed action/result protocol
- explicit analyst approval
- deterministic policy evaluation
- agent-initiated polling rather than an inbound endpoint command listener
- one executable allowlisted demo-fixture action with no arbitrary parameters
- endpoint-side target/type/parameter validation
- crash/retry idempotency for event delivery and the demo action
- hash-chained tamper-evident audit verification
- Agents and Response Actions analyst UI
- SQLite local development and PostgreSQL-ready migrations/Compose
- deterministic and live two-repository v1 acceptance harnesses

The release gates are documented in `docs/V1_ACCEPTANCE.md`.

## After v1 — hardening before broader host actions

The next Response release should prioritize trust and operations rather than adding many actions at once:

1. OIDC analyst authentication and role-based authorization.
2. Agent key rotation/revocation workflows and enrollment lifecycle UI.
3. Rate limiting, request-size limits, retention policy, and encrypted sensitive evidence fields.
4. PostgreSQL backup/restore qualification and deployment hardening.
5. Signed audit checkpoints and optional append-only external retention.
6. Action preconditions, dry-run previews, bounded execution timeouts, and richer rollback metadata.
7. Multi-host incident views and cross-sensor source trust/corroboration.
8. A small expansion of safe diagnostic actions before any higher-impact remediation.

## Later safety gates

Real process termination, service control, firewall modification, quarantine/deletion, or host isolation must not be added simply by extending the action enum. Each capability needs its own narrow parameter schema, endpoint implementation, policy, approval rule, rollback/containment behavior, failure tests, and adversarial validation.

Autonomous remediation and LLM-generated executable commands are outside the v1 design and remain prohibited until a separate security review demonstrates a defensible control model.

A future independent RedLab project can exercise these boundaries in authorized disposable labs, but it is not part of the Response v1 scope.
