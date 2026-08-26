# QuietWard Response v1.2.0-alpha.1 acceptance

Candidate branch: `feature/response-v12-hardening`

Backend version: `1.2.0a1`

This gate is standalone. It does not modify any detector repository. The optional product integration is a Response-owned adapter that reads a local QuietWard detector database read-only; no Response code is added to QuietWard.

## Platform execution model

Release qualification is deliberately split across two native hosts on the **same exact candidate SHA**:

1. **Linux automated finalizer** — `python scripts/finalize_v12_alpha.py` must run on a native Linux host with `/proc/net`. It covers the complete static/local gate plus live Linux process/file containment, the privacy-preserving Linux network diagnostic, and the synthetic schema-compatible QuietWard adapter acceptance.
2. **Windows live gate** — `python scripts/verify_v12_windows_live.py` must run on native Windows. It reuses the same capability-aware disposable process/file containment suite while stamping the server-side host record as Windows, so Windows OS policy and the Windows agent implementation are exercised together.
3. **Installed-service/browser/real QuietWard smoke** — the user-scoped Linux service and limited-current-user Windows task must be validated as documented. On the XPS release host, the Response-owned adapter must also be exercised against the actually installed released QuietWard `v0.5.0-alpha.1` database and that database must remain byte-for-byte unchanged by adapter operation.

Linux PASS does not substitute for Windows PASS, and Windows PASS does not substitute for the Linux `/proc/net` gate.

## Automated Linux gate

From an exact clean checkout of the candidate branch on native Linux:

```text
python scripts/finalize_v12_alpha.py
```

The finalizer must fail closed unless the checkout is the expected repository/branch, tracked state is clean, and the host is Linux.

It runs:

1. Python/backend compile checks.
2. Public-release secret/artifact audits and durable sensitive-persistence audit.
3. Full backend pytest suite with warnings treated as errors.
4. v1.2 exact eight-action typed action/plan surface verification.
5. post-review release-correction source gate.
6. Fresh Alembic migration plus model/migration drift check.
7. Historical Phase 1 database upgrade and audit-chain backfill qualification.
8. `npm ci`, frontend typecheck, production build and high-severity npm audit.
9. public quick-start smoke and cleanup.
10. capability-aware standalone live Response HTTP process/file containment acceptance.
11. Linux live privacy-preserving network-diagnostic acceptance.
12. live read-only QuietWard SQLite → signed Response event/incident/plan acceptance using a schema-compatible isolated fixture.

## Required Windows live gate

On a native Windows checkout of the exact same SHA that passed the Linux finalizer:

```text
python scripts/verify_v12_windows_live.py
```

Required properties:

- the gate refuses to run when the native platform is not Windows;
- server-side host metadata is `Windows`, so registry OS policy is evaluated as Windows rather than Linux;
- the canonical v1.2 agent signs/refreshed capabilities before action dispatch;
- disposable managed-file diagnostic, quarantine and rollback pass;
- a disposable child process receives an opaque handle and exact-process termination passes;
- raw path and raw PID action shapes are rejected;
- generic shell/command action creation is rejected;
- terminal replay does not repeat mutation;
- audit verification remains valid after the live actions.

## Required automated properties

### Control plane and decision quality

- registry is exactly the documented eight-action v1.2 surface;
- every action requires analyst approval;
- server revalidates action registry, parameters, recommendation binding, incident state, host, agent, OS, approval and expiry before dispatch;
- a missing target `HostRecord` is rejected at action creation and again fails closed during policy re-evaluation;
- generic shell/command/script actions remain absent;
- raw `pid`, raw `path`, and raw network-target parameter shapes are rejected;
- process termination/quarantine TTL is at most 240 seconds;
- pre-v1.2 incidents do not receive new executable actions retroactively without persisted recommendation authorization;
- generic `process_start` does not enable termination by itself;
- generic `file_change` does not enable quarantine by itself;
- high-impact process containment requires high/critical privilege escalation or high/critical process evidence containing an explicit high-signal marker;
- high-impact file containment requires malware/YARA, a high/critical newly created executable, or high/critical file evidence with explicit known-bad-hash context;
- read-only family diagnostics remain available for ransomware/vendor event vocabulary even when mutation does not qualify.

### Correlation

- same host/time remains necessary but is not sufficient to merge events;
- same-category coincidence alone does not merge incidents;
- concrete shared process/file/network/persistence indicators can correlate events;
- compatible attack stages can correlate only when at least one event carries explicit high-signal evidence and the evidence reaches high/critical severity;
- explainable correlation reasons identify the shared indicator or compatible attack stages;
- unrelated same-category network events remain separate in an API regression;
- high-signal execution → network evidence joins in an API regression.

### Continuous Response agent

- normal `scripts/poll_response_agent.py` mode runs continuously rather than exiting after one poll;
- `--once` remains available for bounded diagnostics/qualification;
- capabilities are signed/refreshed before every action poll;
- successful polling uses a bounded configurable interval;
- API/network failures use bounded exponential backoff rather than a tight loop;
- SIGTERM/SIGINT cause graceful shutdown;
- Linux user-systemd installation remains user scoped and starts successfully;
- Windows scheduled-task installation remains current-user with `RunLevel Limited`;
- both Linux and Windows installed runtimes include every canonical v1.2 dependency, including `private_state_io.py`;
- the canonical runtime config loader rejects a relative/symlinked/abnormal/oversized credential file and, on POSIX, group/world-readable config;
- agent ledger/demo/handle-context/resource-handle state uses randomized exclusive/no-follow atomic writes and bounded verified no-follow reads;
- remote/non-loopback agent URLs require HTTPS.

### Signed agent capability negotiation

- capability report route is machine/HMAC authenticated rather than analyst-header authenticated;
- enabled actions must be a subset of supported actions;
- unknown action names, including command/shell surfaces, are rejected;
- report explicitly attests `arbitrary_command_execution=false` and the `qwrh1` handle protocol;
- non-demo actions fail policy when the target agent has never reported capabilities;
- a reported-but-locally-disabled high-impact action fails policy;
- capability state older than 15 minutes or implausibly future-dated fails policy;
- a fresh signed report restores evaluation after stale/future state is corrected;
- Linux agents advertise the network diagnostic only on Linux;
- Linux process termination is not advertised if pidfd support is unavailable;
- file mutation is advertised only on Linux/Windows with configured managed roots;
- enrollment performs the first capability sync and continuous polling refreshes it;
- key rotation/recovery preserves the canonical capability set;
- UI offers non-demo actions only on affected agents that signed the exact action as enabled;
- Agents UI exposes signed enabled actions and capability timestamp.

### Separate QuietWard adapter

- `scripts/forward_quietward_events.py` is maintained only in the Response repository;
- adapter opens the QuietWard SQLite database using `mode=ro` and `PRAGMA query_only=ON`;
- adapter never imports the QuietWard Python package and never issues detector INSERT/UPDATE/DELETE statements;
- adapter validates that the database contains at most one host and that it matches the enrolled Response agent host;
- adapter deterministically maps original QuietWard event IDs to stable UUIDv5 Response event IDs;
- stored QuietWard assessment severity/score and privacy-bounded evidence are preserved;
- requests use `source=quietward` through the event-ingestion-only HMAC subkey;
- the event-only adapter credential cannot authenticate action polling;
- adapter keeps a private Response-owned delivery cursor and advances it only after accepted/already-durable duplicate delivery;
- adapter credential and cursor use the shared hardened private-state reader/writer;
- event-ID conflict fails closed;
- replacing/resetting the local detector DB cannot silently strand the cursor above the new rowid range;
- isolated live qualification proves detector DB bytes are unchanged before/after forwarding;
- isolated live qualification proves a high-severity QuietWard reverse-shell event becomes a Response incident exposing process diagnosis and opaque-handle termination eligibility while no generic/raw command action appears;
- Linux and Windows always-on adapter install paths remain user scoped; Windows uses a limited current-user task;
- before publication, the XPS operational gate repeats the bridge check against the actual released QuietWard `v0.5.0-alpha.1` database and verifies that database hash/size/state is unchanged by Response adapter operation.

### Linux network diagnostic

- `collect_network_diagnostic` is Linux-only, low-risk, read-only and accepts no parameters;
- agent reads bounded `/proc/net/{tcp,tcp6,udp,udp6}` state without shell/subprocess execution;
- at most 256 rows are returned and truncation is explicit;
- public rows contain protocol/family, local/remote scope, ports, state, endpoint-local HMAC pseudonym when applicable and an opaque socket handle;
- raw local/remote IP, UID and inode remain agent-local;
- endpoint-local network pseudonym key is a private regular file and never enters API result data;
- network privacy key/state paths reject symlink/reparse-like files, use no-follow verified reads, and retain private directory/file modes;
- unspecified listener endpoints do not emit a meaningless remote-address identity;
- server-supplied network targets are rejected;
- terminal replay does not re-execute the diagnostic;
- no firewall/network mutation or host isolation action is introduced.

### Two-phase agent credential rotation

- only current active key may prepare rotation;
- preparation creates a bounded pending credential without replacing current key;
- pending credential cannot authenticate normal routes before activation;
- only pending credential may activate itself/prove replacement possession;
- current key cannot activate pending credential;
- pending expiry fails closed;
- activation promotes replacement and immediately revokes old key for normal HMAC traffic;
- old key cannot report capabilities, poll, submit results or prepare another rotation after activation;
- disabled agents cannot prepare/activate rotation;
- one-time pending secrets are returned only in no-store responses and do not appear in listings/audit details;
- server retains no usable previous HMAC key material after activation;
- helper writes private `.next`, proves promoted key by capability sync and atomically promotes it using the hardened private-state writer;
- the atomic private-state writer fsyncs file data and best-effort syncs the parent directory after rename;
- `--recover-next` finishes an interrupted promotion using the staged new credential without printing it;
- helper does not print current/pending/promoted secret material.

### Analyst authentication/RBAC

Outside loopback development:

- startup requires `QWR_ANALYST_CREDENTIALS`;
- startup rejects the known development audit-checkpoint signing key;
- invalid bearer returns 401 and cannot fall back to `X-Actor-ID`;
- viewer can read but not mutate;
- responder can change incidents and create/approve/reject actions;
- only admin can enable/disable agents;
- authenticated identity controls audit attribution despite conflicting `X-Actor-ID`;
- machine enrollment/capability/key/action/result routes remain on separate machine authentication;
- viewer may export/verify signed audit checkpoints because those endpoints do not mutate state;
- remote analyst traffic is placed behind TLS/reverse-proxy protection; plain remote HTTP bearer use is not an approved deployment boundary.

### API abuse bounds

- oversized API request receives 413 before normal schema persistence;
- per-client `/api/v1` rate limit produces 429 + `Retry-After`;
- health checks are not consumed by analyst API rate bucket;
- security/no-store response headers remain present.

### Resource handles

- handles are generated by the endpoint, not supplied as raw host identifiers;
- handles have bounded format/expiry;
- provenance is bound locally to incident, host and agent;
- cross-incident reuse is rejected;
- handle state is capacity bounded;
- stale resource identity fails closed;
- consumed-handle replay returns only the matching stored receipt.

### File containment and diagnostic budget

The live gates use only disposable temporary files/directories.

- file diagnostic is read-only and qualified only on Linux/Windows;
- no absolute managed-file path is returned in the diagnostic result;
- symlinks are not eligible;
- each eligible file is capped at 64 MiB;
- total hashing work per diagnostic action is capped at **256 MiB**;
- result reports `scan_byte_budget`, `scanned_bytes`, budget skips and explicit truncation;
- quarantine accepts only an opaque handle;
- source identity/SHA-256 are revalidated immediately before/after containment;
- quarantine produces a separate rollback handle;
- replay does not move again;
- restore refuses occupied original path;
- changed/tampered quarantine object fails closed;
- successful restore returns original disposable bytes.

### Process containment

The live gates create/terminate only their own disposable child process.

- process diagnostic issues an opaque handle for the child;
- raw PID shape is rejected;
- identity is revalidated before termination;
- Linux uses pidfd-bound signaling when enabled;
- Windows rechecks process creation identity;
- agent/self/critical processes remain protected;
- stale/replaced PID fails closed;
- indeterminate interrupted termination fails closed;
- successful gate terminates only the test child and verifies exit;
- terminal replay does not terminate again.

### Audit and signed checkpoints

- action results remain HMAC authenticated;
- terminal result conflict protection remains intact;
- ordinary final audit verification returns `valid: true`;
- checkpoint creation refuses invalid chain;
- checkpoint signatures use independent configured secret;
- trusted startup checkpoint files reject symlink/reparse, non-regular, oversized and group/world-writable POSIX files and verify file identity during read;
- retained checkpoint remains valid after legitimate later appends;
- signature modification fails closed;
- fully recomputed historical chain still fails retained checkpoint prefix verification;
- deleting checkpoint-covered suffix/history fails as missing/truncated history.

## Browser/operational smoke

After the Linux finalizer and Windows live gate pass on the exact same candidate SHA:

1. Start the API/frontend with documented quick start.
2. Install/start a disposable v1.2 endpoint agent using the Linux user-systemd installer and confirm it stays running across multiple poll intervals with fresh capability time.
3. Install/start a disposable v1.2 endpoint agent on Windows using the scheduled-task installer and confirm it remains current-user with `RunLevel Limited`, stays running across multiple poll intervals, and keeps capabilities fresh.
4. Confirm Overview, Incidents, Hosts, Agents and Events render without console errors.
5. Confirm `/health` reports `response_scope=typed_controlled_response_v12`, the finite action count and `generic_command_execution=false`.
6. Confirm Agents shows signed enabled capabilities and latest capability-report time.
7. Feed two unrelated same-category synthetic events and confirm they stay in separate incidents unless they share a concrete indicator.
8. Feed a generic process event and confirm process diagnosis is available but termination is not.
9. Feed qualified high-severity reverse-shell/privilege evidence and confirm handle-bound termination becomes available.
10. Feed a generic file-change event and confirm quarantine is not exposed; feed qualified malware evidence and confirm file diagnostic/quarantine/rollback appear.
11. On Linux, confirm network diagnostic is read-only and firewall/host-isolation remains non-executable.
12. Run diagnostics and confirm handle-backed action UI offers only unexpired handles returned by successful prior actions for same incident/agent.
13. Confirm there is no free-form PID, path, network target, command, or opaque-handle input anywhere in the normal containment workflow.
14. Confirm process choices show bounded process context and managed-file choices show relative path/hash without absolute managed path.
15. Confirm quarantine result makes rollback handle available to restore selector.
16. Rotate agent key, confirm new key ID appears and polling continues without printing secret; confirm old key is rejected immediately.
17. Retain a staged `.next` fixture and confirm `--recover-next` completes recovery without exposing secret.
18. In production/non-loopback config behind TLS, confirm bearer required and viewer cannot mutate; clearing browser session token removes access.
19. Export audit checkpoint, append normal activity and confirm retained checkpoint still verifies historical prefix.
20. On the XPS with released QuietWard `v0.5.0-alpha.1`, record the QuietWard database hash/size, install the Response-owned adapter, create/use only controlled synthetic QuietWard evidence, confirm it appears in Response, and verify the QuietWard database hash/size/state was not modified by Response.
21. Confirm no action UI exposes command, shell, PowerShell, service-name, firewall-rule, raw PID, raw path or raw network-target inputs.

Record exact candidate SHA and PASS/FAIL evidence before tagging/publishing.

## Release decision

`v1.2.0-alpha.1` may be tagged/published only when all of the following are true on the **same exact candidate SHA**:

- `python scripts/finalize_v12_alpha.py` passes on native Linux;
- `python scripts/verify_v12_windows_live.py` passes on native Windows if Windows support is claimed;
- the documented Linux user-service and Windows limited-task startup checks pass;
- every browser/operational smoke item above passes;
- the actual released QuietWard v0.5 adapter smoke passes without modifying QuietWard state;
- the release checklist records the evidence for that exact SHA.

Any failure blocks release.
