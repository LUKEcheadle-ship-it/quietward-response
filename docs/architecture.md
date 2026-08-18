# Architecture

QuietWard Response is a standalone control-plane application. Sensors cross a strict trust boundary at the versioned ingestion API; endpoint implementations are not part of this repository.

## Phase 1 data flow

1. FastAPI validates an event with strict Pydantic models.
2. The ingestion service normalizes strings and persists the event idempotently.
3. The host record is created or refreshed.
4. The deterministic correlator considers recent incidents for that host and records its reasons.
5. The incident service refreshes severity, confidence, title, probable cause, and rule-based recommendations.
6. The timeline is derived chronologically from immutable source events.
7. Audit entries capture state transitions and generated output.
8. The Next.js console reads API projections; it cannot issue endpoint commands.

## Layers

- `api`: HTTP routing and query validation
- `schemas`: external contracts and strict validation
- `services`: ingestion, correlation, incident assessment, timeline, and audit behavior
- `models`: domain persistence entities
- `integrations`: source adapter boundary
- `database`: SQLAlchemy engine, sessions, and declarative base
- `protocol`: vendor-neutral versioned wire contract

SQLite supports local development and tests. Models and queries use SQLAlchemy so PostgreSQL can replace it through `DATABASE_URL`. Alembic owns schema evolution.

## Correlation

The correlator never calls an LLM. It searches non-dismissed incidents on the same host within a configurable five-minute window. It records matches for category, process ID, executable/file path, destination address, and persistence mechanism. Same-host temporal proximity is the baseline, with evidence similarities making the explanation stronger.

## Safety boundary

Recommendations have `diagnostic` or `remediation` type. Phase 1 returns remediation guidance for human planning but exposes no executor, agent callback, or action dispatch API.
