# QuietWard Response v1.1 alpha threat-model delta

This document covers security changes introduced by the `v1.1.0-alpha.1` standalone response-plan expansion. The full v1 threat model still applies to the existing API, agent-auth, approval, action, and audit surfaces.

## New assets

- deterministic incident response plans;
- plan attack-family classification and priority;
- analyst-facing investigation, containment, recovery, and escalation guidance;
- the explicit distinction between guidance and registered executable actions.

## New trust boundary

Validated sensor telemetry can cause Response to generate a plan. The plan is advisory data inside the Response control plane; it is not an endpoint command.

A plan step cannot become executable merely because its text contains words such as quarantine, block, isolate, stop, revoke, lock, patch, or restart. Endpoint execution still requires a separately registered typed action.

## Abuse case: malicious telemetry tries to create an arbitrary command

Controls:

- event input is parsed by strict schemas;
- response-plan generation chooses from hard-coded bounded plan templates;
- event text is not interpolated into a shell or command language;
- response-plan output has no command field;
- the action registry is independent from plan text;
- the alpha registry contains only `restart_quietward_demo_service`;
- action creation rejects unknown action types.

Expected result: malicious telemetry may influence which advisory family is shown, but cannot create a new executable primitive.

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

Controls inherited from v1:

- action creation requires an action type in `ACTION_REGISTRY`;
- the registered demo action rejects non-empty parameters;
- action target agent/host, incident state, recommendation binding, approval, expiry, and deterministic policy are validated;
- agent-authenticated polling and ActionResult requests remain replay resistant;
- there is no shell/PowerShell/cmd/bash action type.

Alpha-specific control: no response-plan family adds an action to `ACTION_REGISTRY`.

Expected result: unsupported action types fail closed before dispatch.

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

Before process termination, quarantine, firewall rules, container stop, account lock, persistence modification, service control, or package/configuration mutation are enabled, each capability needs:

1. a dedicated Response-agent executor;
2. an exact versioned action schema;
3. endpoint-created or endpoint-validated resource identity;
4. short expiry;
5. resource fingerprint/precondition captured locally;
6. endpoint-side revalidation immediately before mutation;
7. bounded timeout and failure behavior;
8. durable execution journal/idempotency;
9. rollback or containment metadata where applicable;
10. least-privilege execution boundary;
11. adversarial validation against stale target, substitution, replay, crash, and rollback failure.

## Result-size hardening

The alpha also bounds agent-supplied structured action data before persistence:

- `result` maximum serialized size: 256 KiB;
- `evidence` maximum serialized size: 64 KiB;
- error text remains separately bounded.

This reduces accidental or malicious database growth through the ActionResult surface. These limits are transport/application safeguards, not a substitute for rate limits or storage retention policies.

## Alpha residual limitations

- `X-Actor-ID` is not production analyst authentication;
- possession of a valid agent HMAC secret still permits impersonation of that agent;
- production source adapters need their own authentication/trust contracts;
- audit chaining is tamper-evident rather than immutable;
- one API process/worker remains the qualified runtime shape;
- real automated containment is intentionally limited to the compatibility demo action;
- response-plan quality is constrained by the quality and completeness of ingested telemetry.
