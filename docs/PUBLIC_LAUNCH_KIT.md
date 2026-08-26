# QuietWard Response public launch kit

This document is the canonical public-launch copy for the qualified QuietWard Response v1.0 line. The exact qualified baseline is `v1.0.0`; current `main` carries the v1.0.1 frontend security-maintenance update without changing the controlled-response runtime surface.

## Launch position

**QuietWard Response is an Apache-2.0 licensed, event-driven incident investigation and controlled-response platform for local and trusted-network security environments.**

It validates security telemetry, correlates related observations into explainable incidents, reconstructs timelines, recommends investigation steps, coordinates explicitly approved typed response actions, and records a tamper-evident audit trail.

The v1.0 executable boundary is intentionally narrow. It demonstrates the complete secure response lifecycle without exposing arbitrary remote administration: the only executable action changes a dedicated QuietWard demo fixture after human approval, deterministic policy evaluation, endpoint-side allowlist validation, and signed result reconciliation.

## Public beta status

- Qualified baseline: `v1.0.0`
- Current maintenance source: `main` (`v1.0.1` frontend security maintenance)
- License: Apache-2.0
- Qualified release branch: `release/v1.0.0`
- Backend/API version: `1.0.0`
- Frontend maintenance version: Next.js `16.3.3`
- Public quick start: `python scripts/bootstrap_local.py`
- Supported public-beta shape: local/trusted-network, single API process/worker
- Intended users: security students, homelab builders, defensive-security researchers, and developers evaluating controlled-response architecture

The existing GitHub `v1.0.0` release/tag is the immutable qualified baseline. Because upstream Critical Next.js advisories were published on August 25, 2026, public-beta users should clone current `main`, which carries the 16.3.3 maintenance fix while preserving the qualified Response behavior.

## Qualification evidence

The qualified v1.0.0 release completed:

- 73 QuietWard Response backend tests
- migration, upgrade, and ORM-drift checks
- frontend TypeScript and production build checks
- high-severity npm audit
- public quick-start startup and clean shutdown verification
- 182 companion QuietWard tests
- real two-repository signed event -> incident -> approval -> action -> result HTTP acceptance
- browser route and incident-lifecycle smoke verification
- tamper-evident audit verification after the response lifecycle

See `docs/V1_ACCEPTANCE.md` for the exact release contract. The v1.0.1 maintenance patch changes the frontend dependency/install path only; it does not expand or alter the executable action surface.

## Short project description

QuietWard Response is a security incident investigation and controlled-response platform that turns authenticated endpoint telemetry into explainable incidents, human-reviewed response decisions, tightly typed endpoint actions, and a verifiable audit trail. It was designed to demonstrate a safer alternative to generic remote-command remediation by requiring explicit action registration, analyst approval, deterministic policy checks, endpoint-side validation, replay resistance, and signed results.

## GitHub release description

### QuietWard Response v1.0.0

The first qualified release of QuietWard Response delivers the complete event-to-response lifecycle:

`authenticated event -> deterministic correlation -> incident -> investigation -> recommendation -> human approval -> deterministic policy -> endpoint allowlist -> controlled action -> signed result -> tamper-evident audit`

Highlights include FastAPI/SQLAlchemy/Alembic backend services, a Next.js analyst console, replay-resistant HMAC endpoint integration, deterministic incident correlation, response approval/policy enforcement, agent-initiated polling, idempotent action/result handling, a public cross-platform bootstrap path, Docker Compose support, and deterministic release qualification.

The v1 executable surface is deliberately limited to a dedicated demo fixture. There is no arbitrary shell, PowerShell, process termination, service control, file deletion/quarantine, firewall modification, host isolation, or autonomous remediation in v1.0.

The release is intended for local/trusted-network public-beta evaluation, homelab use, defensive-security research, and architecture demonstration rather than Internet-facing production deployment.

### v1.0.1 maintenance note

Current `main` updates the frontend from Next.js 16.3.1 to 16.3.3 in response to upstream Critical advisories published August 25, 2026. The backend/API, action registry, policy logic, endpoint action surface, protocol, and audit behavior remain unchanged from the qualified v1.0 baseline.

## Resume / portfolio bullet

**QuietWard Response — Creator / Developer:** Built and qualified an Apache-2.0 incident-response platform using FastAPI, SQLAlchemy/Alembic, Next.js, Docker, HMAC-authenticated endpoint telemetry, deterministic incident correlation, human-approved policy-gated response actions, replay protection, idempotent execution, and tamper-evident auditing; validated the v1.0 release with 73 backend tests, 182 companion endpoint tests, live cross-repository HTTP acceptance, migrations, frontend production builds, and browser lifecycle smoke tests.

## Short resume version

Built QuietWard Response, a FastAPI/Next.js controlled-response platform with authenticated telemetry, deterministic incident correlation, human-approved endpoint actions, replay protection, and tamper-evident auditing; qualified v1.0 through backend/frontend, migration, integration, and live browser testing.

## LinkedIn / social launch copy

I’m releasing QuietWard Response, an open-source project I built to explore a simple question: how can incident-response software move from detection to action without turning into a generic remote-command system?

QuietWard Response is an Apache-2.0 incident investigation and controlled-response platform with authenticated telemetry, deterministic incident correlation, incident timelines, human approval, policy-gated typed actions, endpoint-side validation, replay protection, signed results, and tamper-evident auditing.

The qualified v1.0 baseline completed backend, frontend, migration, cross-repository integration, public-bootstrap, and browser-lifecycle testing. Its executable scope is intentionally limited to a dedicated demo fixture, so the project demonstrates the complete response-control architecture without pretending to be a production EDR/SOAR or unrestricted remediation agent.

Before public launch I also applied the current Next.js 16.3.3 security maintenance update after upstream Critical advisories were published, without expanding the Response action surface.

Repository: https://github.com/LUKEcheadle-ship-it/quietward-response

## Claims that are safe to advertise

- event-driven incident investigation and controlled-response platform
- deterministic and explainable incident correlation
- authenticated endpoint telemetry and replay resistance
- explicit human approval and deterministic response policy
- endpoint-side typed action validation
- idempotent action/result lifecycle
- tamper-evident audit trail
- cross-platform local bootstrap
- Docker/PostgreSQL-ready development path
- qualified v1.0 baseline with documented test and live-integration evidence
- current frontend maintenance source uses Next.js 16.3.3

## Claims not to make for v1.0

Do not describe v1.0 as:

- a production EDR/XDR/SOAR replacement
- an Internet-facing production service
- autonomous remediation
- arbitrary host control
- immutable audit storage
- multi-tenant or horizontally scalable
- enterprise RBAC/OIDC
- a system that prevents or guarantees detection of breaches

## Publication state

- The qualified `v1.0.0` GitHub tag and release already exist and point to the exact qualified source commit.
- Current `main` carries the public-facing documentation plus the v1.0.1 Next.js security-maintenance patch.
- The final account-level publication operation is repository visibility: change `quietward-response` from private to public.
- Publishing the repository must not merge the separate unqualified v1.2 alpha containment branch; that work remains isolated until its own native Linux/Windows acceptance is complete.
