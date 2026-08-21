#!/usr/bin/env python3
from __future__ import annotations

import verify_v12_alpha_live as base
from response_agent_capabilities import sync_capabilities


_original_run_agent_action = base._run_agent_action


def _run_agent_action_with_capability_sync(
    api_url,
    agent,
    incident_id,
    enrollment,
    host_id,
    action_type,
    parameters,
):
    state = sync_capabilities(agent)
    if action_type not in set(state.get("enabled_actions") or []):
        raise RuntimeError(
            f"live gate target agent did not advertise enabled capability {action_type}: {state!r}"
        )
    return _original_run_agent_action(
        api_url,
        agent,
        incident_id,
        enrollment,
        host_id,
        action_type,
        parameters,
    )


def main() -> int:
    base._run_agent_action = _run_agent_action_with_capability_sync
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
