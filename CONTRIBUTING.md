# Contributing

QuietWard Response and QuietWard are separate projects. Changes here must not vendor the QuietWard repository or weaken the serialized protocol boundary between them.

## Development workflow

1. Branch from the appropriate base; do not commit directly to the default branch.
2. Keep API, service, persistence, integration, policy, execution-protocol, and UI responsibilities separated.
3. Add deterministic tests for every behavior or security-boundary change.
4. Preserve the v1 response boundary: no arbitrary command execution or generic host-control action.
5. Any executable action must be typed, explicitly registered, narrowly parameterized, approval-gated, policy-checked, independently validated by the endpoint, idempotent under retries, and auditable.
6. Use synthetic events and dedicated fixtures in tests/examples. Never commit real incident evidence, credentials, private host identifiers, or customer data.

## v1 release verification

Run the repository release gate with a checkout of the companion QuietWard integration branch:

```bash
python scripts/verify_v1.py --quietward-repo ../quietward
python scripts/verify_v1_live.py --quietward-repo ../quietward
```

The first command covers backend tests, migrations, protocol/action-surface checks, frontend typecheck/build/audit, and the QuietWard suite. The second proves the actual local HMAC event and approval-gated action loop over HTTP.

For frontend-only work, the minimum checks remain:

```bash
cd frontend
npm run typecheck
npm run build
npm audit --audit-level=high
```

Do not mark a response capability complete solely because a unit test passes. Changes affecting authentication, approvals, policy, action delivery, or endpoint execution should include failure/replay/crash-path coverage appropriate to the risk.
