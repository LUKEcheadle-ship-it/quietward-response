# Contributing to QuietWard Response

QuietWard Response welcomes contributions that improve investigation, onboarding, portability, and controlled-response reliability without turning the product into a generic remote administration tool.

QuietWard Response and QuietWard are separate projects. Changes here must not vendor QuietWard or weaken the serialized handoff/protocol boundary between them.

## Good places to start

Useful contribution areas that do not require touching executable endpoint capabilities include:

- frontend usability and accessibility;
- documentation, screenshots, and first-run guidance;
- safe synthetic demo scenarios;
- API documentation;
- migration and regression tests;
- Windows/Linux portability;
- sanitized export formats;
- bootstrap/installer ergonomics;
- bridge health and provenance presentation.

See `docs/COMMUNITY_ROADMAP.md` for the current product direction.

## Try the product first

The quickest development-oriented product walkthrough uses only the existing synthetic seed path:

```bash
python scripts/quick_demo.py
```

## Development workflow

1. Branch from the appropriate base; do not commit directly to the default branch.
2. Keep API, service, persistence, integration, policy, execution-protocol, and UI responsibilities separated.
3. Add deterministic tests for every behavior or security-boundary change.
4. Preserve the controlled-response boundary: no arbitrary command execution or generic host-control action.
5. Any executable action must be typed, explicitly registered, narrowly parameterized, approval-gated, policy-checked, independently validated by the endpoint, idempotent under retries, and auditable.
6. Use synthetic events and dedicated fixtures in tests/examples. Never commit real incident evidence, credentials, private host identifiers, or customer data.

## Current paired qualification

For the current QuietWard/Response integration line, the paired diagnostic gate is:

```bash
python scripts/verify_v11_diagnostics.py --quietward-repo ../quietward
```

For frontend-only work, the minimum checks are:

```bash
cd frontend
npm ci
npm run typecheck
npm run build
npm audit --audit-level=high
```

Do not mark a response capability complete solely because a unit test passes. Changes affecting authentication, approvals, policy, action delivery, endpoint execution, replay handling, or crash recovery should include failure-path coverage appropriate to the risk.

## Security issues

Follow `SECURITY.md`. Report vulnerabilities privately. Do not put exploit details, credentials, private endpoint data, or real incident evidence in public issues or pull requests.
