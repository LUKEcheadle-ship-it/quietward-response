from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import AgentRecord
from app.database.session import get_db
from app.schemas.agent import AgentEnrollRequest, AgentEnrollResponse, AgentPatch, AgentRead
from app.services.action_service import cancel_undispatched_actions_for_agent
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


def _actor_id(value: str) -> str:
    resolved = value.strip() or "local-analyst"
    return resolved[:128]


@router.post("/enroll", response_model=AgentEnrollResponse, status_code=status.HTTP_201_CREATED)
def enroll(
    payload: AgentEnrollRequest,
    request: Request,
    response: Response,
    token: str | None = Header(default=None, alias="X-QWR-Enrollment-Token"),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    expected = request.app.state.settings.enrollment_token
    if not token or not hmac.compare_digest(token, expected):
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
        actor_type="system",
        actor_id="agent-enrollment",
        action="agent_enrolled",
        resource_type="agent",
        resource_id=agent.agent_id,
        details={"host_id": agent.host_id, "key_id": agent.key_id},
    )
    db.commit()

    # Enrollment is the only API response that contains the one-time endpoint
    # secret. Explicitly prevent browsers/proxies from caching it.
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
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
    return [_agent_to_dict(item) for item in agents]


@router.get("/{agent_id}", response_model=AgentRead)
def get_agent(agent_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    agent = db.get(AgentRecord, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="agent not found")
    return _agent_to_dict(agent)


@router.patch("/{agent_id}", response_model=AgentRead)
def patch_agent(
    agent_id: str,
    payload: AgentPatch,
    actor_id: str = Header(default="local-analyst", alias="X-Actor-ID"),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    agent = db.get(AgentRecord, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="agent not found")
    previous = agent.enabled
    agent.enabled = payload.enabled
    if previous != agent.enabled:
        record_audit(
            db,
            actor_type="analyst",
            actor_id=_actor_id(actor_id),
            action="agent_enabled" if agent.enabled else "agent_disabled",
            resource_type="agent",
            resource_id=agent.agent_id,
            details={"host_id": agent.host_id},
        )
        if not agent.enabled:
            # Cancels pending, approved, and dispatching lifecycles. Once the
            # endpoint has acknowledged `executing`, result/recovery remains valid.
            cancel_undispatched_actions_for_agent(db, agent.agent_id)
    db.commit()
    db.refresh(agent)
    return _agent_to_dict(agent)
