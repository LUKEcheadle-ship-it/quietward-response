# QuietWard Response v1.2 release-correction record

This document records changes made after a full code/function review of the v1.2 release candidate. These are release corrections, not a command-surface expansion.

Status: **candidate controls — exact-SHA finalizer and browser/platform review still required**.

## Continuous endpoint operation

The official `scripts/poll_response_agent.py` is now a long-running capability-aware agent loop by default. It:

- refreshes signed capabilities before every poll;
- polls on a bounded interval;
- exits cleanly on SIGTERM/SIGINT;
- uses bounded exponential backoff on API/network failure;
- retains `--once` only for qualification/diagnostics.

User-scoped deployment paths are included for:

- Linux: `scripts/install_response_agent_user_service.sh` + `deploy/quietward-response-agent.service`;
- Windows: `scripts/install_response_agent_windows.ps1`, using a limited current-user scheduled task.

## Separate QuietWard adapter

The public QuietWard product remains unchanged by Response integration. The adapter lives only in this repository:

`scripts/forward_quietward_events.py`

It:

- opens QuietWard SQLite using `mode=ro` and `PRAGMA query_only=ON`;
- never imports the QuietWard package;
- never writes the QuietWard database;
- refuses events whose host ID does not match the enrolled Response agent host;
- deterministically maps the original QuietWard event ID to a stable UUIDv5 Response event ID;
- preserves QuietWard assessment severity and bounded privacy-safe evidence;
- sends `source=quietward` events through the least-privilege event-ingestion HMAC credential;
- maintains its own private delivery cursor in the Response agent state directory;
- treats a deterministic duplicate as delivered but fails closed on an event-ID conflict.

Installable always-on paths are included for Linux and Windows:

- `scripts/install_quietward_adapter_user_service.sh`
- `scripts/install_quietward_adapter_windows.ps1`

The adapter is optional: Response remains sensor-neutral in development and can later receive other sensors through separately authenticated adapters. No Response client or action executor belongs in the QuietWard repository.

## Stronger decision quality

### Correlation

Production ingestion now uses `correlation_v12.py`.

Two events are no longer merged merely because they share a category. Correlation requires either:

- a shared concrete process/file/network/persistence indicator; or
- a compatible multi-stage attack-family transition where at least one side contains explicit high-signal evidence and the evidence reaches high/critical severity.

This reduces accidental incident merging while preserving explainable cross-stage attack correlation.

### High-impact recommendation thresholds

Read-only diagnostics remain broadly available when relevant.

`terminate_process_by_handle` is now recommended only for:

- high/critical privilege escalation; or
- high/critical process execution with an explicit high-signal marker such as reverse shell, credential dumping/theft, process injection, web shell, document→interpreter or ransomware-impact evidence.

`quarantine_artifact_by_handle`/rollback are now recommended only for:

- malware-signature/YARA evidence;
- high/critical newly created executables; or
- high/critical file events with explicit known-bad-hash evidence.

A generic process start or generic file change no longer exposes destructive containment in the normal analyst workflow.

## Fail-closed target-host policy

The dispatch policy now rejects an action when its target host identifier has no corresponding `HostRecord`.

This matters because agent/action host identifiers are intentionally stored separately from the host table and therefore a stale/corrupt host reference is possible even when normal API flows would not create one. The policy boundary no longer skips OS-family validation when the host row is missing; it records `TARGET_HOST_MISSING_REASON` and denies dispatch.

Action creation also refuses a missing target host. Regression coverage constructs the stale-host state directly and verifies policy denial.

## Runtime capability truthfulness

The canonical v1.2 agent now reports what the local host can actually execute:

- network diagnostic only on Linux;
- process diagnostics only on Linux/Windows;
- process termination is not enabled on Linux unless pidfd APIs are available;
- file quarantine/restore are enabled only on Linux/Windows with configured managed roots.

The server registry also limits v1.2 process/file mutation to Linux and Windows; `unknown` and unqualified macOS mutation support were removed.

## Agent credential and private-state enforcement

`AgentConfig.from_file()` now fails closed when a POSIX credential file is:

- relative;
- a symlink;
- not a normal file;
- empty/oversized;
- group/world accessible.

The canonical v1.2 runtime additionally routes its local ledger, demo state, handle-context and resource-handle state through `scripts/private_state_io.py`. The helper:

- uses randomized temporary names rather than predictable `.tmp` files;
- opens temporary files with exclusive creation and no-follow flags where supported;
- uses bounded no-follow reads with pre/open/post identity checks;
- rejects link/reparse state files;
- rejects group/world-readable POSIX private state;
- keeps private directories/files permission-hardened;
- cleans temporary files on failure.

The optional QuietWard adapter credential and delivery-cursor paths use the same hardened private-state implementation. Windows installers also reject reparse-point configuration files. OS-backed secret storage remains a later hardening goal.

## Trusted audit-checkpoint file boundary

The optional startup checkpoint is now treated as a security input rather than a plain JSON file. Startup rejects:

- symbolic links/reparse points;
- non-regular files;
- group/world-writable POSIX checkpoint files;
- oversized checkpoints;
- files that change identity during validation/read.

The reader uses a bounded no-follow open and verifies the same file before and after reading before signature/prefix verification proceeds.

## Bounded file diagnostic work

The v1.2 managed-file diagnostic retains its 64 MiB per-file cap and now also has a **256 MiB total hashing budget per action**. Results report:

- `scan_byte_budget`;
- `scanned_bytes`;
- files skipped because the total budget was reached;
- explicit truncation state.

This prevents one read-only approval from unexpectedly hashing up to the theoretical multi-gigabyte sum of every individually allowed file.

## Runtime status accuracy

`/health` now reports:

- `response_scope=typed_controlled_response_v12`;
- the finite action/diagnostic counts;
- `generic_command_execution=false`.

The generic `remediation_enabled` compatibility flag remains false because arbitrary/general host remediation is still intentionally unavailable.

## Qualification additions

The exact-SHA finalizer now includes:

- release-correction static/source gate;
- full backend regression tests for correlation/recommendation thresholds;
- fail-closed missing-host policy regression;
- hardened private-state and adapter-state regression tests;
- trusted checkpoint file-safety regression tests;
- runtime config/OS-capability/file-budget tests;
- standalone adapter unit tests;
- live read-only QuietWard SQLite → authenticated Response incident acceptance;
- existing process/file/network containment and security gates.

These corrections do not constitute a PASS until the complete finalizer and documented browser/platform review run on the final candidate SHA.
