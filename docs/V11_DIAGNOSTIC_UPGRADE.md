# QuietWard Response v1.1 joint diagnostic upgrade preview

Status: **development / not yet release-qualified**

This branch expands the qualified v1 controlled-response architecture into a larger joint QuietWard + Response system. QuietWard remains observation-only; Response owns authenticated ingestion, analyst approval, policy enforcement, endpoint execution, signed results, and audit.

## Joint architecture

```text
QuietWard observations
        |
        v
QuietWard deterministic analysis + evidence chain
        |
        v
private sanitized handoff outbox
        |
        v
Response-owned watcher
        |
        v
Response incident + QuietWard provenance
        |
        v
analyst approval -> deterministic policy
        |
        v
signed-capability Response endpoint agent
        |
        v
bounded read-only diagnostic
        |
        v
signed result + Response audit chain
```

No Response credential or execution loop is embedded in QuietWard.

## New controlled diagnostics

- `collect_host_diagnostic`
  - bounded platform, uptime, CPU-count, load, and agent-state disk capacity
  - no shell execution
- `collect_process_diagnostic`
  - Linux `/proc` or native Windows Toolhelp32 process inventory
  - PID, parent PID, and image basename only
  - no command lines and no full executable paths
- `collect_network_diagnostic`
  - Linux `/proc/net` socket snapshot
  - raw remote addresses are HMAC-pseudonymized on the endpoint before return
  - no packet capture and no network modification

The original `restart_quietward_demo_service` action remains the only mutating action and still affects only the dedicated JSON demo fixture.

## Signed capability binding

New diagnostics are not available merely because an agent is enrolled.

Each v1.1 Response endpoint submits an HMAC-signed capability declaration. Response stores that declaration separately from the legacy v1 enrollment record and checks it during deterministic policy evaluation.

A capability-less v1 agent is treated as **demo-only**. The console also filters target agents using this server-trusted capability set, so an incompatible legacy agent is not presented for a v1.1 diagnostic.

The capability schema cannot represent `arbitrary_command_execution=true`, and policy fails closed if such database state is introduced out of band.

## Automatic QuietWard handoff watcher

`scripts/watch_quietward_handoffs.py` continuously consumes only the dedicated private handoff directory produced by QuietWard.

It does not modify the QuietWard database. For every handoff file it:

1. opens the file with bounded, symlink-resistant checks;
2. validates the exact document, event, metadata, evidence, host, and safety schemas;
3. requires installation-keyed HMAC identities for both the finding and finding subject;
4. verifies the document-level QuietWard cycle/hash matches every embedded event;
5. submits the sanitized event using the Response-owned HMAC credential;
6. treats deterministic duplicate event IDs as successful reconciliation;
7. records a Response-owned consumption ledger;
8. archives the transport file with bounded retention.

A previously processed filename that reappears with different content fails closed.

Manual one-shot import remains available:

```bash
python scripts/ingest_quietward_handoff.py HANDOFF.json \
  --config /ABSOLUTE/PATH/agent-config.json
```

## Privacy-keyed detector identity

Response never needs the raw internal QuietWard finding ID.

QuietWard exports an installation-keyed HMAC finding token and uses that token when deriving the deterministic Response event UUID. This keeps duplicate handling stable on one installation while avoiding publication of an unkeyed detector identifier.

The raw finding subject is independently represented by another installation-keyed HMAC token. Raw command lines, executable paths, file targets, and remote network addresses are excluded by the handoff contract.

## Evidence-chain provenance

Automated QuietWard events stored by Response include:

```text
metadata.quietward_source_cycle_id
metadata.quietward_source_chain_hash
```

The incident console displays this provenance as a trace back to QuietWard's tamper-evident evidence chain, while still hiding raw finding subjects and internal finding IDs.

The dedicated **QuietWard context** panel also shows only sanitized detector information:

- detector finding count;
- highest QuietWard score;
- privacy-keyed subject count;
- signal types;
- correlation codes;
- suggested investigation lanes;
- source evidence-chain cycle/hash;
- explicit `No execution authority` boundary.

## Response endpoint agent

Enroll the separate Response-owned endpoint agent:

```bash
python scripts/enroll_response_agent.py --host-id HOST_ID
```

The helper:

- receives the one-time enrollment secret;
- writes it to a private local config instead of printing it;
- immediately registers the finite signed capability set.

Run continuously:

```bash
python scripts/response_agent.py \
  --config /ABSOLUTE/PATH/agent-config.json
```

The agent keeps a local execution ledger. Crash recovery handles both important acknowledgement windows:

- if local execution started but the server missed `executing`, the agent re-establishes `executing` before continuing;
- if local execution already reached a terminal result but the server missed `executing`, the agent posts `executing` and then replays the stored terminal result **without re-executing the endpoint action**.

The original demo mutation remains action-ID idempotent; the new diagnostics are read-only.

## Linux continuous services

After agent enrollment, install both Response-side systemd user services:

```bash
bash scripts/install_joint_response_user_services.sh \
  /ABSOLUTE/PATH/agent-config.json \
  /ABSOLUTE/PATH/quietward-response-handoff-outbox
```

This installs:

- `quietward-response-agent.service`
- `quietward-response-handoff-watcher.service`

Both use `NoNewPrivileges`, `PrivateTmp`, private umask, and restart-on-failure behavior.

QuietWard provides its own separate outbox user service. The separation is deliberate: the QuietWard service has no Response credential, while the Response services own transport and endpoint actions.

## Joint status

Inspect the live bridge without modifying either system:

```bash
python scripts/joint_status.py \
  --config /ABSOLUTE/PATH/agent-config.json \
  --inbox /ABSOLUTE/PATH/quietward-response-handoff-outbox \
  --pretty
```

The status output covers:

- Response API health;
- agent enabled state/version/capabilities/last-seen;
- pending and archived handoff counts;
- consumption-ledger state;
- the architectural boundary that QuietWard has zero execution authority and Response exposes no arbitrary-command surface.

## Console changes

The Agents page now calls these identities **Response endpoint agents**, not QuietWard agents. It shows each agent's server-trusted enabled actions.

The incident console distinguishes controlled diagnostics from remediation and renders QuietWard provenance/context when a joint handoff contributed to an incident.

## Qualification

Main v1.1 gate:

```bash
python scripts/verify_v11_diagnostics.py \
  --quietward-repo ../quietward
```

That gate is intentionally separate from the frozen v1.0 verifier. It checks:

- Python compilation;
- public-release secret/path audit;
- all backend tests, including crash-lifecycle recovery;
- the exact bounded action surface;
- fresh migrations and upgrade from v1.0 schema;
- frontend clean install, typecheck, production build, and high-severity npm audit;
- public quick-start smoke and cleanup;
- companion QuietWard full test/audit suite;
- QuietWard v0.6 focused handoff/outbox gate;
- the real joint cross-repository acceptance loop.

The joint acceptance starts a real Response API and proves:

```text
QuietWard observation
-> deterministic analysis with actions_executed=0
-> privacy-preserving keyed handoff
-> evidence-chain provenance preservation
-> Response incident
-> analyst approval
-> policy approval
-> real read-only endpoint diagnostic
-> signed terminal result
-> no terminal replay execution
-> valid Response audit chain
```

The dedicated script is:

```bash
python scripts/verify_joint_quietward_response.py \
  --quietward-repo ../quietward
```

Final release still requires the same candidate SHAs to pass native supported-platform qualification before merge/tag/publication.

## Explicitly out of scope

This preview does **not** enable:

- arbitrary shell, PowerShell, cmd, or bash execution;
- arbitrary PID/path/address targets;
- process termination;
- file quarantine or restoration;
- service stop/start outside the dedicated demo fixture;
- firewall modification;
- host/network isolation;
- autonomous remediation.
