# QuietWard Response v1.1.0-alpha.1 acceptance

This document defines the release boundary for the first broad incident-response planning alpha.

## Release identifier

- GitHub release/tag candidate: `v1.1.0-alpha.1`
- backend/API version: `1.1.0a1`
- Response branch: `feature/response-diagnostic-expansion`

This alpha does not replace the historical `v1.0.0` qualification record.

## Product boundary

QuietWard Response is qualified here as a **standalone product**. The alpha gate does not require, modify, or validate any detector repository.

Telemetry enters through the versioned event API or a separately maintained sensor adapter. Response owns correlation, incident state, structured response planning, analyst decisions, controlled-action policy, its bundled outward-polling alpha agent, and audit.

## What the alpha adds

Every incident exposes a deterministic response plan at:

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

Common sensor vocabulary is normalized into those families, including ransomware/trojan, credential spray/brute force/credential dumping, C2/beaconing/exfiltration/lateral movement, scheduled-task/registry/service persistence, container/Kubernetes alerts, CVEs/misconfiguration, defense evasion/tamper, suspicious execution, file-integrity changes, and availability/resource failures.

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

## Bundled Response agent

The alpha includes `scripts/response_agent.py`, a Response-owned standard-library agent that polls outward for approved work and independently validates the complete action envelope.

The agent implements exactly one local action:

`restart_quietward_demo_service`

The action name is retained for v1 API compatibility, but the alpha agent maps it only to its own dedicated JSON demo fixture. It accepts no arbitrary target or parameters.

The agent must:

- authenticate polling and result submission with the existing HMAC protocol;
- verify target agent and host IDs;
- verify schema, action type, empty parameters, policy allowance, lifecycle, expiry, and required approval metadata;
- reject server-only `executing` recovery without matching local execution history;
- persist execution intent before changing the fixture;
- record the applied action ID/result in the fixture;
- retain a terminal ledger for retry/recovery;
- never apply the same action twice;
- contain no subprocess, shell, PowerShell, cmd, service-manager, process-control, firewall, quarantine, account, container-control, or package-management primitive.

`scripts/enroll_response_agent.py` must write the one-time agent secret to a private local config without printing the secret to stdout.

All real containment ideas shown by the plan — quarantine, process stop, network block, host isolation, account/session action, persistence disable, container stop, package/configuration mutation — remain manual/planned/blocked until the bundled Response agent is extended with a separately qualified narrow typed executor for each capability.

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
5. response-family vocabulary/precedence tests;
6. Response-agent config, allowlist, recovery, and exactly-once tests;
7. static proof that the agent/enrollment helper contain no generic host-execution primitive;
8. fresh Alembic migration;
9. Phase-1-to-current migration;
10. Alembic drift check;
11. frontend `npm ci`;
12. frontend typecheck;
13. frontend production build;
14. high-severity npm audit;
15. public quick-start startup and cleanup smoke.

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
- a Response-owned agent can enroll against the API;
- a matching demo incident exposes the demo action;
- explicit analyst approval and deterministic policy are required;
- the Response-owned agent polls outward, validates the action, persists execution intent, changes its dedicated fixture exactly once, and submits a signed result;
- the stored action reaches `succeeded`;
- a second poll does not re-execute the fixture action;
- the Response audit chain remains valid after the acceptance traffic.

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
11. enroll the bundled Response agent using a disposable test host and confirm the helper does not print the one-time secret;
12. run the demo agent workflow and confirm the fixture changes exactly once;
13. change incident status and confirm the UI remains healthy;
14. verify `/api/v1/audit/verify` returns `valid=true`;
15. stop the product and confirm API/frontend ports are released.

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
- container stop automation;
- package/configuration mutation;
- autonomous remediation;
- LLM-generated executable commands.

The alpha may **recommend** or **plan** those response types where appropriate, but it labels them as manual/planned/blocked rather than executable.

## Known limitations

- analyst identity remains development-grade `X-Actor-ID`, not OIDC/RBAC;
- HMAC transport assumes TLS outside loopback/trusted development;
- the alpha enrollment helper stores the agent secret in a permission-hardened local JSON file rather than OS secret storage;
- audit history is tamper-evident, not immutable;
- API qualification remains single-process/single-worker;
- production sensor adapters/authentication are source-specific work outside this alpha;
- the bundled agent implements only the demo fixture; real containment remains guidance until each narrow agent executor is implemented and qualified.

## Publication rule

Do not publish or tag `v1.1.0-alpha.1` unless the complete automated wrapper and manual browser smoke pass on the exact candidate SHA.
