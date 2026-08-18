# Contributing

QuietWard Response and QuietWard are separate projects. Changes here must not modify or vendor the QuietWard sensor repository.

## Development workflow

1. Branch from `main`; do not commit directly to the default branch.
2. Keep API, service, persistence, integration, and UI responsibilities separated.
3. Add deterministic tests for behavior changes.
4. Preserve the Phase 1 safety boundary: no arbitrary commands or endpoint remediation.
5. Run the backend tests, frontend typecheck/build, and dependency audit before proposing a change.

```bash
cd backend
../.venv/bin/python -m pytest -W error

cd ../frontend
npm run typecheck
npm run build
npm audit
```

Use synthetic events in tests and examples. Never commit real incident evidence, credentials, host identifiers, or customer data.
