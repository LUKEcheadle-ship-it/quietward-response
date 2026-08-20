# QuietWard Response v1.1 alpha threat-model delta

This document covers security changes introduced by the `v1.1.0-alpha.1` standalone response-plan and Response-agent expansion. The full v1 threat model still applies to the existing API, agent-auth, approval, action, and audit surfaces.

## New assets

- deterministic incident response plans;
- plan attack-family classification and priority;
- analyst-facing investigation, containment, recovery, and escalation guidance;
- the explicit distinction between guidance and registered executable actions;
- the bundled Response agent's HMAC credential;
- its private local config, durable action ledger, and dedicated demo fixture.

## New trust boundaries

Validated sensor telemetry can cause Response to generate a plan. The plan is advisory data inside the Response control plane; it is not an endpoint command.

Separately, the bundled Response agent polls outward for registered actions. The alpha agent has exactly one local executor and independently validates the received action before touching its dedicated demo fixture.

A plan step cannot become executable merely because its text contains words such as quarantine, block, isolate, stop, revoke, lock, patch, or restart. Endpoint execution still requires a separately registered and agent-allowlisted typed action.

## Abuse case: malicious telemetry tries to create an arbitrary command

Controls:

- event input is parsed by strict schemas;
- response-family inference returns a fixed family identifier, not executable text;
- response-plan generation chooses from hard-coded bounded plan templates;
- event text is not interpolated into a shell or command language;
- response-plan output has no command field;
- the action registry is independent from plan text;
- the alpha registry contains only `restart_quietward_demo_service`;
- action creation rejects unknown action types.

Expected result: malicious telemetry may influence which advisory family is shown, but cannot create a new executable primitive.

## Abuse case: broad vendor category hides a higher-signal event

Control:

- exact canonical event types are checked first;
- high-signal event vocabulary is checked before broad category mapping;
- categories are used only after event-level inference fails.

Example: a ransomware event categorized generically as `execution` still maps to the malware response family.

Residual risk: string inference is an interoperability aid, not a substitute for a source-specific normalized event contract. Unknown vocabulary remains `unknown` and is escalated rather than guessed aggressively.

## Abuse case: analyst mistakes planned guidance for automation

Controls:

- every plan step has an explicit state: `available`, `manual`, `planned`, or `blocked`;
- every plan step separately declares whether it is destructive and whether approval is required;
- `executable_action_type` is null unless the exact step maps to a registered action;
- the incident UI labels planned steps `Planned · not executable`;
- blocked steps are labeled `Blocked · future capability`;
- the controlled-action UI is separate from the plan panel;
- the plan itself returns the exact `executable_actions` list.

Expected result: the UI and API never imply that advisory containment is silently executed.

## Abuse case: compromised Response server tries generic endpoint execution

Controls:

- action creation requires an action type in `ACTION_REGISTRY`;
- the registry contains exactly the demo action;
- the registered demo action rejects non-empty parameters;
- action target agent/host, incident state, recommendation binding, approval, expiry, and deterministic policy are validated server-side;
- the Response agent independently validates allowed fields, required fields, schema, target agent, target host, action type, empty parameters, policy allowance, lifecycle, timestamps, expiry, and approval metadata;
- server-only `executing` recovery is rejected unless matching local execution history exists;
- there is no shell/PowerShell/cmd/bash action type or generic execution method in the agent.

Expected result: unsupported or substituted actions fail closed before local state changes.

## Abuse case: action replay or crash causes the fixture to change twice

Controls:

- request nonces remain replay resistant at the API;
- the agent persists local `executing` intent before the fixture change;
- the dedicated fixture stores the applied action ID and structured result;
- the terminal ledger stores status/result/error;
- re-delivery of the same action reuses stored state/result rather than applying the fixture transition again;
- terminal server state produces no further pending work in the normal path.

Expected result: the demo fixture's restart count increments once per action ID.

## Abuse case: compromised agent credential

Possession of the alpha agent HMAC secret permits impersonation of that enrolled agent within the server's authentication/lifecycle constraints.

Controls:

- credential is bound to one agent/host record;
- agent disable/revocation remains available in the control plane;
- the alpha enrollment helper does not print the one-time secret;
- it writes a user-local config with private-file permissions where POSIX permission semantics are available;
- common agent credential/config filenames are explicitly rejected by the public-release audit if tracked in the repository.

Residual risk: the alpha config file is still local plaintext secret material. Production credential storage should use OS-protected secret storage plus rotation/revocation workflows.

## Abuse case: response plan overreacts to a single low-confidence event

Controls:

- plan priority uses persisted incident severity rather than inventing a new severity model;
- plans preserve the existing incident correlation/evidence context;
- containment steps are primarily manual/planned rather than autonomous;
- plan objectives begin with evidence preservation and scope confirmation;
- high-impact host isolation is explicitly blocked in this alpha.

Residual risk: sensor quality still determines incident quality. Response does not make a compromised sensor truthful merely because its transport is authenticated.

## Abuse case: a plan is treated as a production runbook when evidence is incomplete

Controls:

- every plan includes limitations;
- every plan includes escalation conditions where a family has known high-risk boundaries;
- investigation steps precede containment guidance;
- unknown event families remain advisory and explicitly request escalation;
- the alpha does not claim forensic completeness or autonomous containment.

## Why real containment is still disabled

A safe real responder must know exactly what resource is being changed. Raw server-supplied strings such as PID, file path, service name, IP address, container ID, account name, or package name are not sufficient as a security boundary.

The bundled alpha agent proves the secure lifecycle using only its owned demo fixture. Before process termination, quarantine, firewall rules, container stop, account lock, persistence modification, service control, or package/configuration mutation are enabled, each new executor needs:

1. an exact versioned action schema;
2. endpoint-created or endpoint-validated resource identity/opaque handle;
3. short expiry;
4. resource fingerprint/precondition captured locally;
5. endpoint-side revalidation immediately before mutation;
6. bounded timeout and failure behavior;
7. durable execution journal/idempotency;
8. rollback or containment metadata where applicable;
9. least-privilege execution boundary;
10. adversarial validation against stale target, substitution, replay, crash, partial failure, and rollback failure.

## Result-size hardening

The alpha also bounds agent-supplied structured action data before persistence:

- `result` maximum serialized size: 256 KiB;
- `evidence` maximum serialized size: 64 KiB;
- error text remains separately bounded.

This reduces accidental or malicious database growth through the ActionResult surface. These limits are transport/application safeguards, not a substitute for rate limits or storage retention policies.

## Alpha residual limitations

- `X-Actor-ID` is not production analyst authentication;
- possession of a valid agent HMAC secret still permits impersonation of that agent;
- agent config uses permission-hardened local JSON rather than OS secret storage;
- production source adapters need their own authentication/trust contracts;
- audit chaining is tamper-evident rather than immutable;
- one API process/worker remains the qualified runtime shape;
- real automated containment is intentionally limited to the Response-owned demo fixture;
- response-plan quality is constrained by the quality and completeness of ingested telemetry.
