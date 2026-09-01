# Joint QuietWard + QuietWard Response update

Status: **paired development preview; both pull requests remain draft until same-SHA qualification passes**

Companion branches:

- QuietWard: `feature/v06-response-context`
- QuietWard Response: `feature/v11-diagnostic-response`

Companion pull requests:

- QuietWard `#5`
- QuietWard Response `#6`

## What the pair becomes

This update turns the two repositories into a connected defensive-security workflow while preserving a hard execution boundary:

```text
DETECT                         HAND OFF                       RESPOND

QuietWard                      local private transport        QuietWard Response
---------                      -----------------------        ------------------
read-only collection      ->   sanitized handoff outbox  ->   authenticated ingest
local scoring                  bounded backlog                incident correlation
local correlation              cycle/hash provenance          analyst console
finding evidence               no network credential          approval + policy
hash-chained cycles                                          endpoint diagnostics
zero actions executed                                        signed result + audit
```

The design principle is simple:

> QuietWard can tell Response what it observed, but Response can never turn QuietWard into a remote-command agent.

## Major capabilities in this update

### 1. Automatic one-way handoff

QuietWard can continuously follow its own tamper-evident evidence chain through a read-only database connection and emit sanitized local transport files.

The outbox has:

- deterministic cycle filenames;
- private permissions;
- atomic writes;
- bounded file size;
- bounded pending capacity;
- crash-safe cycle state;
- no network client;
- no Response credential;
- no action execution.

### 2. End-to-end evidence provenance

Automated handoff events carry the exact QuietWard evidence-chain:

- cycle ID;
- chain hash.

Response verifies document/event provenance agreement before ingestion and preserves the cycle/hash on the incident event. The incident UI exposes that provenance without exposing raw finding subjects.

### 3. Keyed cross-system identities

QuietWard does not export raw subjects or raw internal finding IDs.

It derives installation-keyed HMAC identities for:

- the finding subject;
- the QuietWard finding identity.

The Response event UUID is derived from the keyed finding token, preserving deterministic duplicate handling on one installation without publishing the internal finding identifier.

### 4. Response-owned automatic ingestion

A separate Response process watches only the dedicated handoff directory. It:

- performs bounded/symlink-resistant reads;
- validates the exact handoff schema;
- validates host binding;
- validates privacy-keyed identities;
- validates evidence-chain provenance;
- signs event ingestion with the Response credential;
- records a consumption ledger;
- archives processed transport files with bounded retention.

It never writes to the QuietWard database.

### 5. Real read-only endpoint diagnostics

Response adds three analyst-approved actions:

- `collect_host_diagnostic`
- `collect_process_diagnostic`
- `collect_network_diagnostic`

They are parameterless and intentionally exclude generic targeting.

The process diagnostic returns bounded PID/parent/image-basename data without command lines or full executable paths.

The Linux network diagnostic pseudonymizes remote addresses on the endpoint before results leave the host.

### 6. Signed endpoint capability declarations

An enrolled endpoint does not automatically gain the new action set.

The Response endpoint agent signs a capability declaration. Policy checks that declaration before dispatch. Legacy v1 credentials without a declaration remain limited to the original demo-fixture action.

The console uses the same server-trusted capability list when selecting targets.

### 7. Crash-safe response lifecycle

The Response endpoint agent persists local lifecycle state and recovers from lost acknowledgements.

If a crash occurs after local execution starts but before the server records `executing`, the agent re-establishes the execution state before continuing.

If a terminal result is already stored locally, recovery replays the lifecycle/result **without re-executing the endpoint action**.

### 8. Joint analyst console

Response now distinguishes:

- QuietWard detector context;
- controlled diagnostics;
- remediation.

The incident page shows:

- QuietWard finding count;
- highest detector score;
- privacy-keyed subject count;
- signal families;
- correlation codes;
- suggested investigation lanes;
- QuietWard evidence-chain provenance;
- an explicit `No execution authority` detector boundary.

The Agents page now correctly calls execution identities **Response endpoint agents** and displays their signed enabled capabilities.

### 9. Continuous service installers

Linux user-service installers are included for:

- the QuietWard local handoff outbox;
- the Response endpoint agent;
- the Response handoff watcher.

The Response pair uses `NoNewPrivileges`, `PrivateTmp`, a private umask, and restart-on-failure behavior.

### 10. Joint status command

`scripts/joint_status.py` gives a read-only operational view of:

- Response API health;
- endpoint agent state/version/capabilities;
- handoff backlog;
- archive/ledger state;
- the detector/executor security boundary.

## Safety boundary after the update

QuietWard still cannot:

- run arbitrary commands;
- execute Response actions;
- terminate processes;
- quarantine files;
- modify firewall rules;
- isolate hosts;
- control general services;
- hold a Response network credential.

Response still cannot dispatch:

- generic shell/PowerShell/cmd/bash;
- arbitrary PID targets;
- arbitrary path targets;
- arbitrary network-address targets;
- process termination;
- quarantine/restore;
- host isolation;
- firewall changes.

The only mutating action retained is `restart_quietward_demo_service`, and it changes only the dedicated Response JSON demo fixture.

## Joint qualification

The paired release gate is intentionally one command from the Response checkout:

```bash
python scripts/verify_v11_diagnostics.py \
  --quietward-repo ../quietward
```

The gate covers:

1. Response compilation and public-release audit;
2. full Response backend test suite;
3. action-surface lockout checks;
4. fresh migration and v1-to-v1.1 migration;
5. frontend clean install/typecheck/build/audit;
6. public quick-start smoke and cleanup;
7. full QuietWard test/audit suite;
8. QuietWard focused handoff/outbox safety gate;
9. real joint cross-repository acceptance.

The joint acceptance must prove:

```text
QuietWard observation
-> actions_executed = 0
-> sanitized/keyed handoff
-> evidence-chain provenance preserved
-> authenticated Response incident
-> explicit analyst approval
-> deterministic policy allow
-> real read-only endpoint diagnostic
-> signed terminal result
-> no terminal replay execution
-> valid Response audit chain
```

## Release rule

Do not merge or tag either side independently as the joint release.

The release candidate should record the exact QuietWard SHA and exact Response SHA that passed the joint gate. Native supported-platform qualification must then pass on that same pair before both draft PRs are promoted and merged.
