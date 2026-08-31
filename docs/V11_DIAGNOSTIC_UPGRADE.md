# QuietWard Response v1.1 diagnostic upgrade preview

Status: **development / not yet release-qualified**

This branch expands the qualified v1 controlled-response architecture with a separate Response-owned endpoint agent and three analyst-approved, parameterless, read-only diagnostic actions.

## New controlled actions

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

The original `restart_quietward_demo_service` action remains the only mutating action in this preview and still affects only the dedicated JSON demo fixture.

## Capability binding

New diagnostics are not available merely because an agent is enrolled.

Each v1.1 endpoint must submit an HMAC-signed capability declaration. Response stores that declaration separately from the legacy v1 enrollment record and checks it during deterministic action policy evaluation.

A capability-less v1 agent is treated as **demo-only** and can never receive the new diagnostic actions.

The capability schema cannot represent `arbitrary_command_execution=true`, and policy fails closed if such database state is introduced out of band.

## QuietWard integration

The v1.1 importer consumes only `quietward-response-handoff-v1` local files produced by QuietWard's observation-only handoff exporter.

Before transmitting an event to Response it validates:

- host binding to the enrolled Response agent
- exact handoff/event/metadata/evidence key surfaces
- installation-keyed subject pseudonym format
- generic canonical summary text
- bounded event-kind and correlation-signal codes
- coarse operating-system family
- explicit observation-only and zero-executable-authority markers
- absence of raw process, file, network, and persistence objects

The importer, not QuietWard, owns the network credential and signs the existing Response event-ingestion request.

## Enrollment

```bash
python scripts/enroll_response_agent.py --host-id HOST_ID
```

The helper writes the one-time secret to a private local config instead of printing it and immediately registers the finite action capability set with an HMAC-signed request.

Run the agent with:

```bash
python scripts/response_agent.py --config /ABSOLUTE/PATH/agent-config.json
```

Import a QuietWard handoff with:

```bash
python scripts/ingest_quietward_handoff.py HANDOFF.json \
  --config /ABSOLUTE/PATH/agent-config.json
```

## Qualification

Focused/local upgrade gate:

```bash
python scripts/verify_v11_diagnostics.py --quietward-repo ../quietward
```

That gate is intentionally separate from the frozen v1.0 verifier. It checks the expanded but bounded action registry, all backend tests, migrations from fresh and v1 databases, frontend typecheck/build/audit, public quick-start smoke, and optionally the companion QuietWard suite.

Final release still requires live same-SHA endpoint qualification on supported operating systems before merge/tag/publication.

## Explicitly out of scope

This preview does **not** enable:

- arbitrary shell, PowerShell, cmd, or bash execution
- arbitrary PID/path/address targets
- process termination
- file quarantine or restoration
- service stop/start outside the dedicated demo fixture
- firewall modification
- host/network isolation
- autonomous remediation
