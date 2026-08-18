from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import AgentRecord
from app.database.session import get_db
from app.schemas.agent import AgentEnrollRequest, AgentEnrollResponse, AgentRead
from app.services.agent_auth import enroll_agent
from app.services.audit_service import record_audit

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


def _agent_to_dict(agent: AgentRecord) -> dict[str, object]:
    return {
        "agent_id": agent.agent_id,
        "host_id": agent.host_id,
        "display_name": agent.display_name,
        "key_id": agent.key_id,
        "created_at": agent.created_at,
        "last_seen": agent.last_seen,
        "enabled": agent.enabled,
        "agent_version": agent.agent_version,
    }


@router.post("/enroll", response_model=AgentEnrollResponse, status_code=status.HTTP_201_CREATED)
def enroll(
    payload: AgentEnrollRequest,
    request: Request,
    enrollment_token: str | None = Header(default=None, alias="X-QWR-Enrollment-Token"),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    expected = request.app.state.settings.enrollment_token
    if not enrollment_token or not hmac.compare_digest(enrollment_token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_enrollment_token"},
        )
    agent, secret = enroll_agent(
        db,
        host_id=payload.host_id,
        display_name=payload.display_name,
        agent_version=payload.agent_version,
    )
    record_audit(
        db,
        actor_type="local_admin",
        actor_id="enrollment",
        action="agent_enrolled",
        resource_type="agent",
        resource_id=agent.agent_id,
        details={"host_id": agent.host_id, "key_id": agent.key_id},
    )
    db.commit()
    return {
        "agent_id": agent.agent_id,
        "key_id": agent.key_id,
        "secret": secret,
        "host_id": agent.host_id,
        "created_at": agent.created_at,
    }


@router.get("", response_model=list[AgentRead])
def list_agents(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    agents = list(db.scalars(select(AgentRecord).order_by(AgentRecord.created_at.desc())))
    return [_agent_to_dict(agent) for agent in agents]


@router.get("/{agent_id}", response_model=AgentRead)
def get_agent(agent_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    agent = db.get(AgentRecord, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail={"code": "agent_not_found"})
    return _agent_to_dict(agent)
