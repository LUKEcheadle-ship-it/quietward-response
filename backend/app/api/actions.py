from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database.models import ActionRecord
from app.database.session import get_db
from app.schemas.action import ActionCreate, ActionRead, ActionResultCreate, ApprovalDecision
from app.services.action_registry import public_action_registry
from app.services.action_service import (
    ActionError,
    action_to_dict,
    apply_action_result,
    create_action,
    decide_action,
    list_incident_actions,
    pending_actions_for_agent,
)
from app.services.agent_auth import verify_agent_request

router = APIRouter(prefix="/api/v1", tags=["response-actions"])


def _action_error(exc: ActionError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={"code": "action_conflict", "message": str(exc)},
    )


def _actor_id(value: str) -> str:
    resolved = value.strip() or "local-analyst"
    return resolved[:128]


def _validate_result_clock(payload: ActionResultCreate, *, replay_window_seconds: int) -> None:
    maximum = datetime.now(timezone.utc) + timedelta(seconds=replay_window_seconds)
    for field_name in ("started_at", "completed_at"):
        value = getattr(payload, field_name)
        if value is not None and value.astimezone(timezone.utc) > maximum:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "code": "action_result_timestamp_too_far_in_future",
                    "field": field_name,
                },
            )


def _validate_result_transition(db: Session, action_id: str, payload: ActionResultCreate) -> None:
    """Require the endpoint to acknowledge execution before reporting a terminal result.

    This keeps the persisted lifecycle truthful: an approved action becomes
    `dispatching` when polled, then the endpoint must report `executing`, and only
    then may it report `succeeded` or `failed`. The QuietWard client already follows
    this sequence; this guard prevents a compromised/buggy client from skipping it.
    """
    action = db.get(ActionRecord, action_id)
    if action is None:
        return  # apply_action_result returns the canonical unknown-action conflict.
    if action.status == "dispatching" and payload.status in {"succeeded", "failed"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "action_requires_executing_state",
                "message": "endpoint must report executing before a terminal action result",
            },
        )


@router.get("/actions/registry")
def action_registry() -> list[dict[str, object]]:
    return public_action_registry()


@router.post("/incidents/{incident_id}/actions", response_model=ActionRead, status_code=201)
def request_action(
    incident_id: str,
    payload: ActionCreate,
    request: Request,
    actor_id: str = Header(default="local-analyst", alias="X-Actor-ID"),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    try:
        action = create_action(
            db,
            incident_id=incident_id,
            payload=payload,
            actor_id=_actor_id(actor_id),
            default_ttl_seconds=request.app.state.settings.action_default_ttl_seconds,
        )
    except ActionError as exc:
        raise _action_error(exc) from exc
    db.commit()
    return action_to_dict(action)


@router.get("/incidents/{incident_id}/actions", response_model=list[ActionRead])
def incident_actions(incident_id: str, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    return [action_to_dict(item) for item in list_incident_actions(db, incident_id)]


@router.post("/actions/{action_id}/approve", response_model=ActionRead)
def approve_action(
    action_id: str,
    payload: ApprovalDecision,
    actor_id: str = Header(default="local-analyst", alias="X-Actor-ID"),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    try:
        action = decide_action(
            db,
            action_id=action_id,
            actor_id=_actor_id(actor_id),
            approve=True,
            reason=payload.reason,
        )
    except ActionError as exc:
        raise _action_error(exc) from exc
    db.commit()
    return action_to_dict(action)


@router.post("/actions/{action_id}/reject", response_model=ActionRead)
def reject_action(
    action_id: str,
    payload: ApprovalDecision,
    actor_id: str = Header(default="local-analyst", alias="X-Actor-ID"),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    try:
        action = decide_action(
            db,
            action_id=action_id,
            actor_id=_actor_id(actor_id),
            approve=False,
            reason=payload.reason,
        )
    except ActionError as exc:
        raise _action_error(exc) from exc
    db.commit()
    return action_to_dict(action)


@router.get("/agents/{agent_id}/actions/pending", response_model=list[ActionRead])
async def pending_agent_actions(
    agent_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    raw = await request.body()
    agent = verify_agent_request(
        db,
        request,
        raw,
        replay_window_seconds=request.app.state.settings.agent_replay_window_seconds,
    )
    if agent.agent_id != agent_id:
        raise HTTPException(status_code=403, detail={"code": "agent_path_mismatch"})
    actions = pending_actions_for_agent(db, agent)
    db.commit()
    return [action_to_dict(item) for item in actions]


@router.post("/actions/{action_id}/result", response_model=ActionRead)
async def action_result(
    action_id: str,
    payload: ActionResultCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    raw = await request.body()
    replay_window_seconds = request.app.state.settings.agent_replay_window_seconds
    # Revocation stops new telemetry and polling immediately, but a credential that
    # was disabled after an action reached `executing` must still be able to report
    # or idempotently retry that tightly bound action result. Lifecycle/ownership
    # validation below prevents a disabled credential from creating new work.
    agent = verify_agent_request(
        db,
        request,
        raw,
        replay_window_seconds=replay_window_seconds,
        allow_disabled=True,
    )
    if payload.action_id != action_id:
        raise HTTPException(status_code=422, detail={"code": "action_path_mismatch"})
    _validate_result_clock(payload, replay_window_seconds=replay_window_seconds)
    _validate_result_transition(db, action_id, payload)
    try:
        action = apply_action_result(db, agent=agent, payload=payload)
    except ActionError as exc:
        raise _action_error(exc) from exc
    db.commit()
    return action_to_dict(action)
