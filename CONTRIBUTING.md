# Contributing

1. Create a focused branch from `main`.
2. Keep the protocol backwards-compatible within a major schema version.
3. Add deterministic tests for backend behavior and run `pytest backend/tests -q`.
4. Run `npm run build` in `frontend` for UI changes.
5. Never add secrets, production telemetry, malware samples, or an arbitrary command path.
6. Open a pull request describing the behavior, security impact, and checks performed.

Python code should remain typed and separated into API, schema, service, integration, and persistence layers. Frontend code should keep accessible semantics and represent unavailable response controls honestly.
