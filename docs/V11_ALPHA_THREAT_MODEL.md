# QuietWard Response v1.1 alpha threat-model delta

This document covers only the security changes introduced by the `v1.1.0-alpha.1` diagnostic-response expansion. The full v1 threat model still applies.

## New assets

- bounded recent QuietWard diagnostic evidence held in endpoint memory;
- diagnostic action type and lifecycle state;
- signed diagnostic ActionResult content;
- local endpoint ledger entries for diagnostic execution/retry state.

## New trust boundary

Response can now request one of eight predefined read-only diagnostic bundles from an enrolled QuietWard endpoint after analyst approval and policy evaluation.

Response still cannot supply the resource selector used by a shell/OS API. The alpha diagnostic actions accept an empty parameter object only.

## Abuse case: compromised Response tries arbitrary command execution

Control:

- server action registry contains only the v1 demo action plus eight named diagnostic actions;
- every diagnostic rejects non-empty parameters;
- QuietWard independently allowlists the same action names;
- QuietWard diagnostic execution calls only `build_diagnostic_result(...)` over already-collected in-memory evidence;
- no shell, PowerShell, cmd, subprocess, process-control, firewall, service-manager, account-manager, package-manager, or file-mutation primitive is reachable from the new diagnostic executor.

Expected result: fail closed.

## Abuse case: compromised Response tries target substitution

Control:

- HMAC-authenticated polling is bound to the exact enrolled agent;
- action payload must target the exact local agent ID and host ID;
- endpoint revalidates target agent, target host, action type, empty parameters, policy allowance, lifecycle status, approval metadata presence, timestamps, and expiry;
- `executing` recovery requires matching local action history.

Expected result: wrong-agent/wrong-host/stale or unknown actions fail closed.

## Abuse case: diagnostic request used as unrestricted forensic exfiltration

Control:

- only event families already observed by QuietWard can appear;
- diagnostics are bounded to 80 matching events and 40 correlated findings;
- the endpoint retains only a bounded recent context cache for this path;
- the diagnostic result does not invoke a fresh arbitrary filesystem/network/process search;
- existing QuietWard privacy transformations remain in effect before evidence reaches the diagnostic layer.

Residual risk: a compromised approved Response analyst can request bounded evidence that the endpoint has already shared or is prepared to share with Response. Production deployments still need real analyst authentication/RBAC.

## Abuse case: result replay or lifecycle skipping

Controls inherited from v1:

- signed ActionResult requests;
- stored action/agent/host binding;
- `dispatching -> executing -> terminal` transition requirement;
- duplicate terminal result must match stored status/result/error/evidence;
- endpoint durable ledger prevents normal terminal work from being treated as new;
- replay-resistant HMAC nonces remain single-use.

## Abuse case: stale evidence is mistaken for a fresh host scan

Control:

- action/result names are explicitly `collect_*_diagnostic`, but the alpha documentation defines them as bounded recent evidence retrieval;
- result includes explicit `read_only=true` and `system_state_changed=false` metadata;
- the alpha does not claim it performs an unrestricted on-demand forensic scan.

Residual risk: analysts must interpret returned event timestamps. A future version can add explicit age/freshness metadata and optionally trigger narrowly defined read-only collectors.

## Abuse case: diagnostic result causes endpoint state mutation

Control:

- diagnostic builder has no mutating dependency;
- only the local action ledger changes as protocol state;
- the result explicitly states host system state was not changed;
- the released demo fixture remains the only endpoint action that intentionally changes any non-ledger local state.

## Why real containment is still disabled

QuietWard intentionally removes or pseudonymizes several raw target identifiers before persistence, including raw usernames, remote addresses, and container IDs. Passing a raw PID/path/IP/service/container identifier from Response would weaken that privacy and trust boundary and could enable target substitution.

Before process termination, quarantine, firewall rules, container stop, account lock, or package/configuration mutation are enabled, each capability needs:

1. endpoint-created opaque resource handle;
2. short expiry;
3. resource fingerprint/precondition captured locally;
4. exact action-specific parameter schema using the opaque handle only;
5. endpoint-side resource revalidation immediately before mutation;
6. bounded timeout;
7. durable execution journal;
8. rollback or containment metadata;
9. least-privilege execution boundary;
10. adversarial validation against stale-handle, substitution, replay, and rollback failure.

## Alpha residual limitations

- `X-Actor-ID` is still not analyst authentication;
- HMAC shared-secret possession still allows endpoint impersonation for that agent;
- audit chaining is tamper-evident rather than immutable;
- one API process/worker remains the qualified runtime shape;
- recent in-memory diagnostic context is lost on endpoint restart;
- no autonomous containment/remediation is enabled.
