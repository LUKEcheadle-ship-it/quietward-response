# QuietWard Response v1.2.0-alpha.1 marketing kit

Use this material only after the exact release candidate passes `scripts/finalize_v12_alpha.py` and the documented browser smoke. Preserve **experimental alpha** language.

## Positioning

**One-line description**

QuietWard Response is a standalone controlled-response platform that turns authenticated security telemetry into explainable incidents, structured response plans and narrowly typed analyst-approved endpoint actions.

**Short tagline**

Controlled response without a generic remote shell.

**Repository/About description**

Incident investigation and controlled response with deterministic policy, analyst approval, typed endpoint actions, opaque resource handles, continuous endpoint agents and tamper-evident audit controls.

## Core story

Most early response tools choose between being too passive or exposing a dangerous remote-command surface. QuietWard Response takes a narrower approach:

- telemetry can influence investigation, but cannot invent executable action types;
- every action is explicitly registered and schema-bounded;
- analyst approval and deterministic policy are required;
- the endpoint independently verifies target identity and local capability enablement;
- real process/file containment uses endpoint-issued opaque handles rather than server-supplied PID/path values;
- the official endpoint agent runs continuously while maintaining signed capability freshness;
- no generic shell, PowerShell, cmd, bash or model-generated command path exists.

QuietWard remains a separate public product. When the two are used together, a **Response-owned read-only adapter** reads QuietWard's local SQLite event store in read-only mode, translates events into the Response wire schema and sends them using the enrolled Response-agent credential. Response code is not placed inside QuietWard.

## v1.2 launch highlights

- deterministic incident response plans across common attack families;
- stronger correlation requiring shared concrete indicators or compatible high-signal attack stages rather than same-category coincidence;
- eight-action finite response surface;
- read-only host/process/file diagnostics;
- Linux read-only network diagnostic with endpoint-local pseudonymous remote identity;
- exact process termination by short-lived opaque handle when strongly justified and locally enabled;
- managed-root artifact quarantine and rollback for strongly justified malware/file evidence;
- 256 MiB total file-diagnostic hashing budget;
- signed agent capability negotiation;
- continuous Linux/Windows user-scoped endpoint operation;
- optional read-only QuietWard→Response adapter with deterministic retry-safe event IDs;
- two-phase key rotation with immediate old-key revocation;
- viewer/responder/admin RBAC;
- request-size and rate limits;
- credential-like field redaction before persistence;
- signed externalizable audit checkpoints;
- integrity-compromise trust freeze for state-changing actions;
- analyst UI that does not expose raw PID/path/handle entry for containment.

## Intended audience

Good fit for:

- security engineers experimenting with controlled response architecture;
- homelab/self-hosting users who want review-first response workflows;
- developers studying endpoint-agent trust and typed remediation design;
- portfolio/research demonstrations of deterministic security control planes.

Do not position v1.2 as an enterprise SOAR platform, mature EDR replacement or autonomous incident responder.

## Launch post — short

QuietWard Response v1.2.0-alpha.1 is the first release candidate of my controlled-response project with narrowly executable real containment.

It adds typed process termination and reversible file quarantine through short-lived endpoint-issued resource handles, plus a continuously running capability-aware agent, signed endpoint capabilities, RBAC, key rotation, sensitive-data redaction, signed audit checkpoints and a privacy-preserving Linux network diagnostic.

A separate read-only adapter can forward local QuietWard findings/events into Response without putting response code inside QuietWard or giving the adapter host-mutation authority.

The design intentionally has no generic remote shell. Execution still requires a registered action, analyst approval, deterministic policy and independent endpoint checks.

Experimental alpha—not autonomous remediation.

## Launch post — LinkedIn / portfolio

I’ve been building QuietWard Response as a security-engineering project around one question: how do you make automated response useful without turning an endpoint agent into an unrestricted remote administration tool?

The v1.2 alpha candidate introduces the first real containment actions: exact process termination and reversible managed-file quarantine, both targeted through short-lived opaque handles issued from the endpoint’s own local observation. The server cannot submit a raw PID or filesystem path.

The control plane adds signed endpoint capability negotiation, analyst RBAC, two-phase key rotation, request/rate bounds, credential-like field redaction, tamper-evident audit checkpoints and an integrity-compromise trust freeze. The endpoint agent runs continuously with bounded retry/backoff. A Linux network diagnostic provides bounded connection context while keeping raw addresses local and returning only endpoint-keyed pseudonymous destination identity.

QuietWard remains separate. An optional Response-owned adapter opens its SQLite evidence store read-only, translates events deterministically and forwards them through the normal authenticated Response protocol.

The system deliberately does not expose shell/PowerShell/cmd/script execution and does not allow response-plan text to become executable code.

It is still an experimental alpha, but the project is intended to demonstrate what a defensible controlled-response architecture can look like before expanding the command surface.

## Portfolio / resume bullet

Built QuietWard Response, a standalone incident-response control plane with deterministic correlation/planning, analyst RBAC, HMAC-authenticated continuous endpoint agents, opaque-handle process/file containment, read-only detector integration, replay protection, signed audit checkpoints and adversarial security release gates.

## Demo narrative

A clean marketing/reviewer demo should use only disposable fixtures:

1. Show QuietWard producing a local privacy-bounded event or create an equivalent synthetic sensor event.
2. If demonstrating the combined workflow, show the Response adapter reading QuietWard SQLite read-only and the incident appearing in Response.
3. Show deterministic incident classification and Response Plan.
4. Show signed endpoint capabilities on the Agents page.
5. Run a read-only diagnostic.
6. Show the UI selecting an endpoint-issued opaque handle rather than entering a PID/path.
7. Approve a disposable process termination or managed-file quarantine.
8. Show the signed result and audit trail.
9. Restore the quarantined disposable file using the rollback handle.
10. Export/verify an audit checkpoint.
11. End by showing that shell/raw-target/network-mutation controls do not exist.

Never use a real user process/file for a public demo.

## Claims safe after qualification

- standalone incident-investigation and controlled-response platform;
- finite eight-action v1.2 registry;
- analyst approval + deterministic policy for all registered actions;
- continuously running HMAC-authenticated outward-polling agent on qualified Linux/Windows paths;
- exact process termination by opaque handle on qualified platforms;
- managed-root reversible artifact quarantine/restore on qualified Linux/Windows paths;
- Linux read-only privacy-preserving network diagnostic;
- optional read-only QuietWard adapter maintained entirely in the Response repository;
- no generic remote shell/command action;
- bearer RBAC for non-loopback/non-development deployments;
- signed audit checkpoints that can anchor retained history.

## Claims to avoid

Do not claim:

- “production-ready SOAR”;
- “enterprise EDR”;
- “autonomous incident response”;
- “AI automatically remediates attacks”;
- “immutable audit log”;
- “prevents breaches”;
- automatic firewall/host-isolation/account/container/persistence remediation that is not present in v1.2;
- that every QuietWard finding is automatically contained;
- that the adapter modifies or embeds code into QuietWard.

## Release materials to surface

At publication, point reviewers/users to:

- `README.md`
- `docs/releases/v1.2.0-alpha.1.md`
- `docs/V12_REVIEW_GUIDE.md`
- `docs/V12_RELEASE_CORRECTIONS.md`
- `docs/V12_ALPHA_THREAT_MODEL.md`
- `docs/V12_ADVERSARIAL_REGRESSION_MATRIX.md`
- `docs/V12_ALPHA_ACCEPTANCE.md`
- `docs/V12_RELEASE_CHECKLIST.md`
- `SECURITY.md`

The release announcement should state the exact qualified candidate SHA and explicitly identify the release as an experimental alpha.
