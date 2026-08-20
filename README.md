# QuietWard Response

QuietWard Response is an event-driven incident investigation and controlled-response platform. It validates sensor events, tracks hosts, deterministically correlates related observations into incidents, reconstructs timelines, recommends investigation steps, and records a tamper-evident audit trail.

The released v1 line adds an optional two-way QuietWard integration: authenticated endpoint telemetry, replay-resistant agent polling, explicit human approval, deterministic policy evaluation, and one deliberately isolated demo remediation. The v1.1 alpha candidate expands that control plane with eight approval-gated, parameter-free, read-only diagnostic actions across QuietWard's major event families. There is still **no arbitrary command execution** and no general host-remediation surface.

> **Candidate status:** this feature branch is the `v1.1.0-alpha.1` candidate (`1.1.0a1`). It retains the released `v1.0.0` demo lifecycle and adds read-only diagnostics for process/privilege, network, persistence, file/malware, container, identity/authentication, vulnerability/configuration, and QuietWard integrity evidence. Publication remains blocked until the complete automated alpha wrapper and documented browser smoke pass on the exact pushed candidate branches. See [v1.1 alpha acceptance](docs/V11_ALPHA_ACCEPTANCE.md) and [v1.1 threat-model delta](docs/V11_ALPHA_THREAT_MODEL.md).

> **Released status:** `v1.0.0` remains the first public controlled-response release. Its final release qualification passed on 2026-08-19 with 73 Response backend tests, migrations/drift checks, frontend typecheck/build/audit, 182 QuietWard tests, the real two-repository HTTP loop, quick-start cleanup, and a live browser UI smoke.

## Relationship with QuietWard

| Project | Responsibility |
|---|---|
| **QuietWard** | Detection, endpoint telemetry, endpoint-side validation, optional polling of approved typed actions |
| **QuietWard Response** | Correlation, investigation, recommendations, approval/policy, response coordination, and audit |

Neither project requires the other to exist. QuietWard remains fully functional when Response integration is disabled or unavailable.

## Architecture

```mermaid
flowchart TD
    Q[QuietWard / other sensors] -->|signed event| I[Event ingestion]
    I --> N[Validation and normalization]
    N --> C[Deterministic correlation]
    C --> X[Incident]
    X --> T[Timeline and evidence]
    T --> R[Assessment and recommendations]
    R --> P[Human approval + deterministic policy]
    P -->|typed approved action| A[Agent-initiated polling]
    A --> E[QuietWard endpoint allowlist]
    E -->|v1 demo fixture or v1.1 read-only diagnostic| Z[Controlled action]
    Z -->|signed ActionResult| X
    I --> U[Hash-chained audit]
    P --> U
    Z --> U
```

See [architecture](docs/architecture.md), [event/action protocol](protocol/README.md), [threat model](docs/threat-model.md), [v1 acceptance](docs/V1_ACCEPTANCE.md), [v1.1 alpha acceptance](docs/V11_ALPHA_ACCEPTANCE.md), [v1.1 threat-model delta](docs/V11_ALPHA_THREAT_MODEL.md), and [roadmap](docs/roadmap.md).

## Quick start

Requirements: Python 3.12+, Node.js 22+, npm, and Git.

```text
git clone https://github.com/LUKEcheadle-ship-it/quietward-response.git
cd quietward-response
python scripts/bootstrap_local.py
```

On Windows, `py -3.12 scripts\bootstrap_local.py` is also supported when Python is installed through the Python launcher.

`bootstrap_local.py` is the cross-platform first-run path. It creates a private local `.env` if needed, replaces the known development enrollment token with a random local token, creates/reconciles the Python virtual environment, installs dependencies, applies database migrations, installs frontend dependencies when needed, starts the API and frontend, and refuses to report ready unless both are reachable. It also terminates the full product process groups on shutdown so the API and frontend ports are released cleanly.

A normal startup begins with a clean incident database; it does **not** inject synthetic incidents.

- Frontend: <http://localhost:3001>
- API: <http://localhost:8002>
- API docs: <http://localhost:8002/docs>
- Health: <http://localhost:8002/health>
- Audit verification: <http://localhost:8002/api/v1/audit/verify>

Press `Ctrl+C` to stop both services.

### Bash launchers

Linux/macOS users can also use the Bash wrappers:

```bash
bash scripts/bootstrap_local.sh
```

For a manually managed `.env`:

```bash
cp .env.example .env
# replace QWR_ENROLLMENT_TOKEN with a random 24+ character value
bash scripts/run_all.sh
```

To populate the original three safe synthetic investigation scenarios after startup:

```text
python scripts/seed_demo.py --api-url http://localhost:8002
```

You can also set `QWR_SEED_DEMO=true` before startup when you specifically want those demo incidents created automatically.

### Run components separately

```bash
bash scripts/run_backend.sh
bash scripts/run_frontend.sh
```

The frontend launcher reads the repository API configuration so a local `QWR_API_PORT` / `NEXT_PUBLIC_API_URL` override does not leave the browser pointing at the default API port.

### Docker Compose

Docker Compose uses PostgreSQL and maps the API and frontend to loopback only. Set a non-empty enrollment token before startup:

```bash
cp .env.example .env
# replace QWR_ENROLLMENT_TOKEN in .env
docker compose up --build
```

## Enroll a QuietWard endpoint

Start Response first, then enroll the endpoint once:

```text
python scripts/enroll_quietward.py --host-id YOUR_QUIETWARD_HOST_ID
```

The enrollment helper reads the Response URL and enrollment token from the repository `.env` by default. You can still override either with `--api-url` or `--token`.

The command prints these one-time endpoint values:

```text
QUIETWARD_RESPONSE_ENABLED=true
QUIETWARD_RESPONSE_URL=http://127.0.0.1:8002
QUIETWARD_RESPONSE_AGENT_ID=...
QUIETWARD_RESPONSE_KEY_ID=...
QUIETWARD_RESPONSE_SECRET=...
```

Store the secret securely on the endpoint. Response stores derived HMAC key material rather than the original enrollment secret, but that derived material is still secret-equivalent.

Authenticated agent requests bind the HTTP method, target path/query, Unix timestamp, random nonce, and SHA-256 body digest into an HMAC-SHA256 signature. The server enforces a bounded replay window and persists used agent nonces.

## v1.1 read-only diagnostics

The alpha candidate adds these approval-gated actions:

- `collect_process_diagnostic`
- `collect_network_diagnostic`
- `collect_persistence_diagnostic`
- `collect_file_diagnostic`
- `collect_container_diagnostic`
- `collect_identity_diagnostic`
- `collect_vulnerability_diagnostic`
- `collect_integrity_diagnostic`

They accept **no parameters**. QuietWard independently allowlists them and returns only bounded recent evidence that QuietWard has already observed in the running endpoint process. Every result declares `read_only=true`, `system_state_changed=false`, `fresh_scan_performed=false`, an explicit evidence scope/time range, record-count bounds, and a 256 KiB serialized result ceiling.

The incident console labels these actions **Read-only diagnostic · Approval required**. It separately labels the v1 demo action **State-changing demo · Approval required**.

## v1 controlled response demo

The only state-changing endpoint action remains:

`restart_quietward_demo_service`

Despite the name, this does **not** restart an operating-system service. It modifies only a dedicated QuietWard-owned JSON demo fixture named `quietward-response-demo.json`. The endpoint rejects arbitrary action types, arbitrary service names, executable paths, shell fragments, and non-empty parameters.

On the QuietWard integration build, initialize the fixture as unhealthy and send its authenticated event:

```text
python scripts/quietward_response_demo.py init-unhealthy --host-id YOUR_QUIETWARD_HOST_ID
python scripts/quietward_response_demo.py sync --host-id YOUR_QUIETWARD_HOST_ID
```

Response creates an incident and exposes the allowlisted recommendation. In the incident console:

1. Choose the intended enabled QuietWard agent if more than one credential exists for an affected host.
2. Prepare the controlled action.
3. Approve it.
4. Run another QuietWard `sync` or normal service cycle.
5. QuietWard polls for the approved action, validates it locally, changes only the dedicated demo fixture, and returns a signed result.
6. Response shows the terminal result and records the lifecycle in the audit chain.

The endpoint persists execution intent and a terminal-result ledger, and the dedicated fixture records the applied action ID. This allows an interrupted `executing` action to be reconciled without changing the fixture twice. Event retries treat only an identical already-accepted event ID as successful delivery; reusing an event ID with different content is rejected as an integrity conflict.

## API

Core endpoints:

- `POST /api/v1/events`
- `GET /api/v1/events`
- `GET /api/v1/hosts`
- `GET /api/v1/hosts/{host_id}`
- `GET /api/v1/incidents`
- `GET /api/v1/incidents/{incident_id}`
- `PATCH /api/v1/incidents/{incident_id}`
- `GET /api/v1/overview`

Controlled-response endpoints:

- `POST /api/v1/agents/enroll`
- `GET /api/v1/agents`
- `GET /api/v1/agents/{agent_id}`
- `PATCH /api/v1/agents/{agent_id}`
- `GET /api/v1/actions/registry`
- `POST /api/v1/incidents/{incident_id}/actions`
- `GET /api/v1/incidents/{incident_id}/actions`
- `POST /api/v1/actions/{action_id}/approve`
- `POST /api/v1/actions/{action_id}/reject`
- `GET /api/v1/agents/{agent_id}/actions/pending` — agent-authenticated
- `POST /api/v1/actions/{action_id}/result` — agent-authenticated
- `GET /api/v1/audit/verify`

Events claiming `source=quietward` require authenticated agent delivery when `QWR_REQUIRE_AGENT_AUTH_FOR_QUIETWARD_EVENTS=true`. Synthetic/development sources remain available for the local demo; outside development, unauthenticated generic sensor sources fail closed until they have an authenticated adapter.

## v1.1 alpha verification

The complete candidate gate is:

```text
python scripts/finalize_v11_alpha.py --quietward-repo ../quietward
```

It runs the full static/local gate, the released v1 live lifecycle as a regression check, and the real v1.1 diagnostic HTTP lifecycle. See [docs/V11_ALPHA_ACCEPTANCE.md](docs/V11_ALPHA_ACCEPTANCE.md) for the exact automated and browser-smoke requirements.

The frozen v1 verification remains available for the released line:

```text
python scripts/finalize_v1.py --quietward-repo ../quietward
```

## Safety status

QuietWard Response remains a controlled local/trusted-network response system, not an unrestricted remote administration service.

Current alpha guarantees are deliberately narrow:

- no shell/PowerShell/cmd/bash action
- no arbitrary process termination
- no arbitrary service control
- no file deletion/quarantine
- no firewall modification
- no host isolation
- no arbitrary account mutation
- no package/configuration mutation
- no LLM-generated command execution
- agent-initiated polling instead of an inbound endpoint command listener
- eight parameter-free read-only diagnostics requiring human approval and deterministic policy validation
- one state-changing demo-fixture action requiring human approval and deterministic policy validation
- bounded diagnostic record counts and serialized result size
- server-side ActionResult result/evidence size validation before persistence

The current line is intentionally qualified as a **single-process/single-worker** API. Both the native launcher and backend container enforce one Uvicorn worker because request serialization protects the linear audit-chain append model. Do not horizontally scale this version against one database; multi-worker support requires a database-backed atomic audit append/head mechanism and requalification.

Analyst identity is still local-development grade (`X-Actor-ID`) rather than OIDC/RBAC. HMAC should be carried over TLS outside loopback/local trusted development. The audit chain provides tamper evidence, not immutability.

Licensed under Apache-2.0.
