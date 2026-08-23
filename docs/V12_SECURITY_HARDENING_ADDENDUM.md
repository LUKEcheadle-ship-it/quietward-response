# QuietWard Response v1.2 security hardening addendum

Status: **candidate controls — full finalizer and browser smoke still required**

This document records hardening added after the initial `v1.2.0-alpha.1` design was drafted. It supplements the threat model and acceptance document and is intentionally conservative: a control listed here is not considered release-qualified until the exact candidate SHA passes the repository finalizer and browser smoke.

## Endpoint authority is explicit, fresh, and revocable

For every non-legacy v1.2 action, Response requires a recent HMAC-signed endpoint capability report. The endpoint signs the exact supported and locally enabled action set and attests that arbitrary command execution is disabled.

Current invariants:

- no capability report → no non-demo v1.2 action;
- action missing from `enabled_actions` → no action;
- capability state older than 15 minutes → no action;
- capability state implausibly in the future → no action;
- action creation preflights capability state;
- approval/policy rechecks capability state;
- dispatch rechecks capability state again;
- UI uses the same freshness window and hides stale/un-attested targets;
- Agents UI labels capability state **Fresh / Stale / Never reported**;
- a disabled agent cannot refresh capability trust state;
- disabling an agent clears capability state and any staged key rotation;
- re-enabling an agent does not restore response authority until a fresh signed capability report arrives.

The legacy demo-fixture action remains the only compatibility exception for agents predating capability reporting.

## Agent credential rotation has no old-key grace traffic

Rotation is prepare → prove pending key → activate:

1. current key prepares a short-lived replacement;
2. only one unexpired pending rotation may exist at a time;
3. the replacement secret is staged locally in a private `.next` configuration before activation;
4. only the pending replacement can activate itself;
5. activation promotes the replacement and immediately invalidates the old key for normal agent traffic;
6. the new key must then prove itself with a normal signed capability sync;
7. `.next` is atomically promoted over the old private config;
8. interrupted local promotion can be completed with `--recover-next` using the staged **new** credential.

The unreleased v1.2 database schema deliberately has **no retired HMAC key material column**. It retains only `previous_key_id` and `previous_key_revoked_at` for audit correlation. A second prepare cannot overwrite a live pending credential. Explicit analyst disable destroys pending rotation state.

Remaining limitation: the active and pending HMAC verification keys are symmetric credential-equivalent material on the Response server. A later hardening milestone should move to vetted encrypted-at-rest key storage or an asymmetric agent-signature protocol. Do not implement custom cryptography for this.

## Compromised evidence freezes host mutation

When an incident contains explicit evidence/sensor/self-integrity compromise, Response may still perform low-risk diagnostics, but medium/high-impact host mutation is denied by deterministic policy.

This prevents process termination or quarantine from being authorized on telemetry that Response already has reason not to trust. The check is bounded, event-driven, and re-evaluated with normal action policy before dispatch.

## Credential loss prevention before persistence

A deterministic redaction layer removes obvious credential-bearing fields and common text patterns before durable storage in the primary high-risk paths:

- validated event payloads and summaries;
- action result data/evidence/errors;
- analyst approval/rejection notes;
- central audit details before they enter the hash chain.

Examples include passwords, passphrases, bearer/access/refresh/session tokens, Authorization/Cookie fields, API/client secrets, credentials and private-key fields. Useful structural values such as `key_id` and `token_count` are not removed merely because their names contain `key` or `token`.

The redaction traversal is depth-bounded. Redaction is loss prevention, **not database encryption**. Incident evidence remains sensitive. The release gate also runs tracked-artifact and durable-persistence audits so a new caller cannot silently reintroduce obvious credential-bearing values.

## Signed audit anchors can be enforced at startup

Response can export and verify signed historical audit checkpoints using a secret independent from the database.

If an externally retained checkpoint is configured through an absolute `QWR_TRUSTED_AUDIT_CHECKPOINT_PATH`, startup fails closed when:

- the file is missing or malformed;
- the checkpoint signature is invalid;
- the anchored historical prefix was consistently rewritten/rehashed;
- audit history covered by the checkpoint was truncated;
- the configured file is unexpectedly large;
- on POSIX, the file is a symlink, non-regular object, or group/world writable.

Legitimate audit rows appended after the checkpoint do not invalidate the historical anchor.

`scripts/manage_audit_checkpoint.py` provides a bounded export/verify workflow. It refuses non-loopback plain HTTP, supports interactive or environment-provided bearer authentication, writes checkpoint JSON atomically/private, and never stores the bearer token in the checkpoint.

This is not WORM/immutable external audit storage. Operational assurance depends on genuinely independent retention of the checkpoint and protection of its signing secret.

## High-impact targeting stays opaque and provenance-bound

The v1.2 containment model remains unchanged:

- no raw PID action parameter;
- no raw file path action parameter;
- no raw network target action parameter;
- no shell/PowerShell/cmd/bash/script action;
- process/file mutators accept only `qwrh1_...` local handles;
- handles are incident/host/agent bound;
- handles expire;
- target identity is revalidated immediately before mutation;
- process termination and quarantine action TTLs are capped at 240 seconds;
- rollback has its own bounded restore window;
- high-impact agent features remain locally disabled unless explicitly opted in.

The normal browser UI does not provide a free-form handle box: it offers only unexpired handles returned by successful prior actions for the same incident and selected agent.

## Network investigation stays read-only

`collect_network_diagnostic` is a Linux-only v1.2 investigation action. It reads bounded `/proc/net` state without a shell/subprocess path, returns no raw network address/UID/inode, caps public rows at 256 with explicit truncation, and issues opaque local socket handles for correlation. It accepts no network target parameter and cannot modify firewall state or isolate a host.

## Current v1.2 release blockers

Before `v1.2.0-alpha.1` can be tagged/published:

1. exact clean candidate checkout must pass `python scripts/finalize_v12_alpha.py`;
2. full backend pytest must pass with warnings as errors;
3. fresh + historical database migration paths must pass;
4. frontend `npm ci`, typecheck, production build and high-severity audit must pass;
5. capability-aware live disposable process/file containment must pass;
6. Linux live privacy-preserving network diagnostic acceptance must pass;
7. signed capability freshness, key rotation, trust-reset, integrity-freeze, redaction and checkpoint tests must pass;
8. tracked-artifact and durable sensitive-persistence audits must pass;
9. documented browser smoke must pass on the same SHA;
10. no detector repository may be required or modified;
11. public-release secret/artifact audit must pass.

Do not convert missing qualification into a documentation exception. Any failed gate blocks release.

## Post-alpha security priorities

The next improvements that materially raise assurance are infrastructure/authentication work rather than widening the command surface:

1. protect active server-side agent verification keys with vetted encrypted-at-rest storage or move to asymmetric endpoint signatures;
2. OS-backed secret storage for local Response-agent credentials;
3. enterprise OIDC/SSO integration on top of the current RBAC model;
4. shared atomic rate/replay/audit primitives before multi-worker deployment;
5. immutable or independently managed audit retention;
6. platform-specific filesystem containment primitives that further narrow the final verify→move race;
7. only then qualify additional typed containment families such as temporary network rules, persistence objects, containers and identity/session controls.

Generic remote administration and model-generated executable commands remain outside the design.
