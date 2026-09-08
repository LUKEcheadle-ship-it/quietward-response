# Try QuietWard Response

The quickest way to understand the product is to start the normal local stack with safe synthetic investigation data already loaded:

```bash
python scripts/quick_demo.py
```

Windows:

```powershell
py -3.12 scripts\quick_demo.py
```

The helper uses the existing local bootstrap and existing synthetic seed path. It does not enable a generic command surface or destructive endpoint capability.

Once startup completes, open:

- analyst console: <http://localhost:3001>
- API: <http://localhost:8002>
- API docs: <http://localhost:8002/docs>

The seeded data is designed to make the incident/timeline workflow visible immediately rather than leaving a first-time user with an empty console.

## What to look at

1. Open the incident list.
2. Inspect the event timeline and recommendation reasoning.
3. Review the distinction between recommendation, approval, policy, and execution.
4. Open the endpoint-agent page to see capability-aware targeting.
5. Review QuietWard provenance when using the paired integration.

## Safety reminder

The current preview still has no generic shell / PowerShell / cmd / bash action, no arbitrary PID/path/network-address targeting, and no autonomous remediation. The existing demo mutation only changes the dedicated JSON fixture documented in the main README.

For the full paired architecture, see `docs/JOINT_QUIETWARD_RESPONSE_UPDATE.md`.
