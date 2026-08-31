from __future__ import annotations

from sqlalchemy.orm import Session

from app.database.capabilities import AgentCapabilityRecord
from app.database.models import AgentRecord


LEGACY_ACTIONS = {"restart_quietward_demo_service"}


def agent_enabled_actions(session: Session, agent: AgentRecord) -> set[str]:
    """Return the server-trusted action set for an enrolled endpoint.

    Capability-less v1 agents retain only the original demo action. New actions
    require an authenticated capability report stored by Response.
    """
    record = session.get(AgentCapabilityRecord, agent.agent_id)
    if record is None:
        return set(LEGACY_ACTIONS)
    if record.arbitrary_command_execution:
        # This should be unrepresentable through the public schema, but fail closed
        # if database state is corrupted or modified out of band.
        return set()
    supported = set(record.supported_actions or [])
    enabled = set(record.enabled_actions or [])
    return supported & enabled


def agent_enables_action(session: Session, agent: AgentRecord, action_type: str) -> bool:
    return action_type in agent_enabled_actions(session, agent)
