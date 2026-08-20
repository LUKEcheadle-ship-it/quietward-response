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

The required release wrapper, with the companion QuietWard integration checkout available, is:

```bash
python scripts/finalize_v1.py --quietward-repo ../quietward
```

That wrapper verifies the exact expected GitHub repositories/feature branches and remote parity, then runs publication audits, the full backend suite, migration/upgrade/drift checks, frontend clean install/typecheck/build/high-severity audit, public quick-start smoke, the complete QuietWard suite, and the real two-repository HMAC event/approval/action/result loop.

The underlying deterministic/live gates remain available separately for debugging:

```bash
python scripts/verify_v1.py --quietward-repo ../quietward
python scripts/verify_v1_live.py --quietward-repo ../quietward
```

For frontend-only work, the minimum checks remain:

```bash
cd frontend
npm ci
npm run typecheck
npm run build
npm audit --audit-level=high
```

Do not mark a response capability complete solely because a unit test passes. Changes affecting authentication, approvals, policy, action delivery, or endpoint execution should include failure/replay/crash-path coverage appropriate to the risk.
