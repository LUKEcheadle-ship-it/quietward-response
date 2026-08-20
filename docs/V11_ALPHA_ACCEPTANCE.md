# QuietWard Response v1.1.0-alpha.1 acceptance

This document defines the release boundary for the first broad incident-response planning alpha.

## Release identifier

- GitHub release/tag candidate: `v1.1.0-alpha.1`
- backend/API version: `1.1.0a1`
- Response branch: `feature/response-diagnostic-expansion`

This alpha does not replace the historical `v1.0.0` qualification record.

## Product boundary

QuietWard Response is qualified here as a **standalone product**. The alpha gate does not require, modify, or validate any detector repository.

Telemetry enters through the versioned event API or a separately maintained sensor adapter. Response owns correlation, incident state, structured response planning, analyst decisions, controlled-action policy, and audit.

## What the alpha adds

Every incident now exposes a deterministic response plan at:

`GET /api/v1/incidents/{incident_id}/response-plan`

The plan covers these response families when relevant:

- malware and suspicious files;
- process execution and privilege escalation;
- identity/authentication compromise;
- persistence;
- suspicious network activity;
- container compromise;
- vulnerabilities and security configuration weaknesses;
- sensor/evidence integrity;
- operational failures that may overlap security events.

Each plan includes:

- priority;
- attack-family classification;
- response objectives;
- investigation steps;
- containment steps;
- recovery steps;
- escalation conditions;
- explicit step state (`available`, `manual`, `planned`, or `blocked`);
- exact executable-action list;
- limitations.

Plan text is never converted into an executable command.

## Executable action surface

The action registry must contain exactly:

`restart_quietward_demo_service`

That compatibility/demo action accepts no arbitrary parameters and remains approval/policy gated.

All real containment ideas shown by the alpha — quarantine, process stop, network block, host isolation, account/session action, persistence disable, container stop, package/configuration mutation — must remain manual/planned/blocked until a dedicated Response agent implements and qualifies a narrow typed executor.

## Automated static/local gate

Run:

```text
python scripts/verify_v11_alpha.py
```

It must pass:

1. backend and script compile checks;
2. public-release audit;
3. complete backend pytest suite with warnings as errors;
4. standalone response-plan action-surface verification;
5. fresh Alembic migration;
6. Phase-1-to-current migration;
7. Alembic drift check;
8. frontend `npm ci`;
9. frontend typecheck;
10. frontend production build;
11. high-severity npm audit;
12. public quick-start startup and cleanup smoke.

No companion detector checkout is accepted as an argument or touched by this gate.

## Automated live HTTP gate

Run:

```text
python scripts/verify_v11_alpha_live.py
```

It starts a migrated single-worker Response API on loopback and proves:

- synthetic development telemetry can create incidents through the real HTTP API;
- malware, privilege, identity, persistence, network, container, vulnerability, and integrity events each map to the correct response-plan family;
- each non-demo plan contains investigation guidance;
- non-demo plans expose zero executable actions;
- attempting to submit an advisory diagnostic name as an endpoint action fails as `unsupported action type`;
- the public action registry contains exactly the demo-fixture action;
- the audit chain remains valid after the acceptance traffic.

## Complete automated wrapper

On the exact clean pushed candidate branch run:

```text
python scripts/finalize_v11_alpha.py
```

The wrapper verifies the expected Response repository/branch/version, then runs both automated gates above.

## Manual browser smoke before publication

After the automated wrapper passes:

1. start Response using `python scripts/bootstrap_local.py`;
2. create or seed at least one non-demo security incident;
3. open the incident page;
4. confirm the **Response plan** panel appears;
5. confirm the plan shows attack family and priority;
6. confirm investigation, containment, and recovery steps are readable;
7. confirm planned containment says `Planned · not executable`;
8. confirm blocked future capabilities say `Blocked · future capability`;
9. confirm the controlled-action panel does not offer a generic command or a fake diagnostic executor;
10. if a demo incident is used, confirm the demo action is separately labeled `State-changing demo · Approval required`;
11. change incident status and confirm the UI remains healthy;
12. verify `/api/v1/audit/verify` returns `valid=true`;
13. stop the product and confirm API/frontend ports are released.

## Alpha safety boundary

Not enabled:

- arbitrary shell / PowerShell / cmd / bash;
- generic command execution;
- arbitrary process termination;
- arbitrary service control;
- file deletion or quarantine automation;
- firewall modification automation;
- host isolation automation;
- arbitrary account/session mutation;
- package/configuration mutation;
- autonomous remediation;
- LLM-generated executable commands.

The alpha may **recommend** or **plan** those response types where appropriate, but it must label them as manual/planned/blocked rather than executable.

## Known limitations

- analyst identity remains development-grade `X-Actor-ID`, not OIDC/RBAC;
- HMAC transport assumes TLS outside loopback/trusted development;
- audit history is tamper-evident, not immutable;
- API qualification remains single-process/single-worker;
- production sensor adapters/authentication are source-specific work outside this alpha;
- most real containment remains guidance until the separate Response agent layer is implemented and qualified.

## Publication rule

Do not publish or tag `v1.1.0-alpha.1` unless the complete automated wrapper and manual browser smoke pass on the exact candidate SHA.
