from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database.capabilities import AgentCapabilityRecord
from app.database.session import get_db
from app.schemas.capability import AgentCapabilitiesReport, AgentCapabilityRead
from app.services.action_registry import ACTION_REGISTRY
from app.services.agent_auth import verify_agent_request
from app.services.audit_service import record_audit


router = APIRouter(prefix="/api/v1/agents", tags=["agent-capabilities"])


def _as_dict(record: AgentCapabilityRecord) -> dict[str, object]:
    return {
        "agent_id": record.agent_id,
        "agent_version": record.agent_version,
        "supported_actions": list(record.supported_actions or []),
        "enabled_actions": list(record.enabled_actions or []),
        "arbitrary_command_execution": bool(record.arbitrary_command_execution),
        "updated_at": record.updated_at,
    }


@router.post("/{agent_id}/capabilities", response_model=AgentCapabilityRead)
async def report_capabilities(
    agent_id: str,
    payload: AgentCapabilitiesReport,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    raw = await request.body()
    agent = verify_agent_request(
        db,
        request,
        raw,
        replay_window_seconds=request.app.state.settings.agent_replay_window_seconds,
        allow_disabled=False,
    )
    if agent.agent_id != agent_id:
        raise HTTPException(status_code=403, detail={"code": "agent_path_mismatch"})

    unknown = sorted(set(payload.supported_actions) - set(ACTION_REGISTRY))
    if unknown:
        raise HTTPException(
            status_code=422,
            detail={"code": "unknown_agent_capability", "actions": unknown},
        )

    now = datetime.now(timezone.utc)
    record = db.get(AgentCapabilityRecord, agent.agent_id)
    if record is None:
        record = AgentCapabilityRecord(
            agent_id=agent.agent_id,
            agent_version=payload.agent_version,
            supported_actions=sorted(payload.supported_actions),
            enabled_actions=sorted(payload.enabled_actions),
            arbitrary_command_execution=False,
            updated_at=now,
        )
        db.add(record)
    else:
        record.agent_version = payload.agent_version
        record.supported_actions = sorted(payload.supported_actions)
        record.enabled_actions = sorted(payload.enabled_actions)
        record.arbitrary_command_execution = False
        record.updated_at = now

    record_audit(
        db,
        actor_type="agent",
        actor_id=agent.agent_id,
        action="agent_capabilities_reported",
        resource_type="agent",
        resource_id=agent.agent_id,
        details={
            "host_id": agent.host_id,
            "agent_version": payload.agent_version,
            "supported_actions": sorted(payload.supported_actions),
            "enabled_actions": sorted(payload.enabled_actions),
            "arbitrary_command_execution": False,
        },
    )
    db.commit()
    db.refresh(record)
    return _as_dict(record)


@router.get("/{agent_id}/capabilities", response_model=AgentCapabilityRead)
def get_capabilities(
    agent_id: str,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    record = db.get(AgentCapabilityRecord, agent_id)
    if record is None:
        raise HTTPException(status_code=404, detail="agent capabilities not reported")
    return _as_dict(record)
