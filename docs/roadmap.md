# Roadmap

## v1 — controlled response foundation

The released v1 foundation established:

- versioned event protocol and strict ingestion;
- host inventory and persistent event store;
- explainable deterministic correlation;
- incident timelines and rule-based cause assessment;
- authenticated agent enrollment and HMAC request authentication;
- separately versioned typed action/result protocol;
- explicit analyst approval;
- deterministic policy evaluation;
- agent-initiated polling rather than an inbound command listener;
- one executable allowlisted demo-fixture action with no arbitrary parameters;
- target/type/parameter/lifecycle validation;
- replay/crash idempotency controls;
- hash-chained tamper-evident audit verification;
- Agents and Response Actions analyst UI;
- SQLite local development and PostgreSQL-ready migrations/Compose.

The historical v1 qualification record is documented in `docs/V1_ACCEPTANCE.md`.

## v1.1 alpha — broad response planning

The current alpha candidate expands **what Response knows how to handle** without pretending all response types are already safe to automate.

It adds structured response plans for:

- malware and suspicious files;
- process execution and privilege escalation;
- identity/authentication compromise;
- persistence;
- suspicious network activity;
- container compromise;
- vulnerabilities and configuration weaknesses;
- sensor/evidence integrity;
- operational failures that may overlap security incidents.

Each plan separates investigation, containment, recovery, escalation, and executable actions. Manual/planned/blocked capabilities are labeled explicitly.

The alpha remains standalone and sensor-neutral. No detector repository must contain Response code.

## Next — dedicated Response agent

Real endpoint capabilities belong to a **dedicated Response agent maintained in this repository**, not in QuietWard or another detector product.

The first Response-agent release should provide only the security primitives needed to make narrow actions safe:

1. authenticated enrollment and outward polling using the existing agent protocol;
2. endpoint-created opaque resource handles for processes, files, network targets, containers, identities, persistence objects, services, and packages/configuration targets;
3. short handle expiry and target fingerprints;
4. read-only precondition/preview requests;
5. durable execution journal and exactly-once/idempotent result behavior;
6. endpoint-side action allowlist and schema version checks;
7. bounded execution timeout and failure reporting;
8. rollback metadata where a rollback is meaningful;
9. least-privilege execution boundary;
10. adversarial validation for stale handle, target substitution, replay, crash, partial failure, and rollback failure.

## First real containment actions

After the Response agent foundation is qualified, add actions one at a time in roughly this order:

1. bounded process-tree diagnostics;
2. artifact hash/metadata diagnostics;
3. network/listener diagnostics;
4. persistence diagnostics;
5. container diagnostics;
6. temporary network block with automatic expiry and rollback;
7. stop an exact container identity;
8. suspend/terminate an exact process identity;
9. quarantine an exact artifact with evidence preservation and restore metadata;
10. disable an exact persistence object with preserved original state;
11. provider-specific session revocation/account lock;
12. host isolation only after a management-path exception and automatic rollback are proven.

Package/configuration mutation should follow only after platform-specific maintenance and rollback handling exists.

## Control-plane hardening

Before higher-impact automation is considered production-ready:

1. OIDC analyst authentication and role-based authorization;
2. agent key rotation/revocation workflows and enrollment lifecycle UI;
3. rate limiting, request-size limits, retention policy, and encrypted sensitive evidence fields;
4. PostgreSQL backup/restore qualification and deployment hardening;
5. signed audit checkpoints and optional append-only external retention;
6. dry-run previews, action preconditions, bounded timeouts, and richer rollback metadata;
7. multi-host incident views and cross-sensor source trust/corroboration;
8. shared atomic replay/audit-head mechanisms before any multi-worker deployment.

## Permanent safety rules

Real process termination, service control, firewall modification, quarantine/deletion, account mutation, package/configuration changes, or host isolation must never be added simply by extending an enum.

Each executor requires its own narrow schema, endpoint implementation, policy, approval rule, rollback/containment behavior, failure tests, and adversarial qualification.

Autonomous remediation and LLM-generated executable commands remain prohibited unless a separate security review establishes a defensible control model.

RedLab remains a separate future project and is not part of this Response alpha.
