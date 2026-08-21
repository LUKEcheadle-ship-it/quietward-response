from __future__ import annotations

from typing import Any

from response_agent import ResponseAgent


def capability_report(agent: ResponseAgent) -> dict[str, Any]:
    capabilities = agent.capabilities()
    read_only = [str(item) for item in capabilities.get("read_only_actions", [])]
    mutating = {
        str(key): bool(value)
        for key, value in dict(capabilities.get("mutating_actions", {})).items()
    }
    supported = sorted(set(read_only) | set(mutating))
    enabled = sorted(set(read_only) | {key for key, value in mutating.items() if value})
    return {
        "schema_version": "1.0",
        "agent_version": "1.2.0-alpha.1",
        "supported_actions": supported,
        "enabled_actions": enabled,
        "resource_handle_protocol": "qwrh1",
        "arbitrary_command_execution": False,
    }


def sync_capabilities(agent: ResponseAgent) -> dict[str, Any]:
    target = f"/api/v1/agents/{agent.config.agent_id}/capabilities"
    response = agent._request("POST", target, capability_report(agent))
    if not isinstance(response, dict):
        raise RuntimeError("Response API returned an invalid capability-report response")
    reported = set(response.get("enabled_actions") or [])
    expected = set(capability_report(agent)["enabled_actions"])
    if reported != expected:
        raise RuntimeError("Response API capability state does not match the signed agent report")
    return response
