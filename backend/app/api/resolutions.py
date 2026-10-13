from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.analyst_auth import authenticated_analyst
from app.database.session import get_db
from app.schemas.incident import IncidentPatch
from app.schemas.resolution import (
    CheckpointInput, DecisionInput, EscalationInput, RebaselineInput, VerificationInput, WorkflowCreate,
)
from app.services import resolution_service as service
from app.services.incident_service import incident_to_detail, update_incident
from app.services.resolution_playbooks import catalog

router = APIRouter(prefix="/api/v1", tags=["guided human recovery"])
PREFIX = "/incidents/{incident_id}/resolution-workflows"


def named_actor(request: Request) -> str:
    if not request.app.state.settings.analyst_token_hashes:
        service.fail("Configure named analyst authentication before recording or approving recovery; loopback demo is read-only", 403)
    return authenticated_analyst(request)


@router.get("/resolution-playbooks")
def playbooks(request: Request) -> dict:
    configured = bool(request.app.state.settings.analyst_token_hashes)
    return catalog() | {"named_auth_configured": configured,
                        "actor": authenticated_analyst(request) if configured else None}


@router.get(PREFIX)
def list_cases(incident_id: str, db: Session = Depends(get_db)) -> dict:
    return service.list_workflows(db, incident_id)


@router.post(PREFIX, status_code=201)
def start_case(incident_id: str, data: WorkflowCreate, db: Session = Depends(get_db),
               actor: str = Depends(named_actor)) -> dict:
    return service.start(db, incident_id, data, actor)


@router.post(PREFIX + "/{workflow_id}/approve")
def approve(incident_id: str, workflow_id: str, data: DecisionInput,
            db: Session = Depends(get_db), actor: str = Depends(named_actor)) -> dict:
    return service.approve(db, incident_id, workflow_id, data, actor)


@router.post(PREFIX + "/{workflow_id}/checkpoints")
def checkpoint(incident_id: str, workflow_id: str, data: CheckpointInput,
               db: Session = Depends(get_db), actor: str = Depends(named_actor)) -> dict:
    return service.checkpoint(db, incident_id, workflow_id, data, actor)


@router.post(PREFIX + "/{workflow_id}/verify")
def verify(incident_id: str, workflow_id: str, data: VerificationInput,
           db: Session = Depends(get_db), actor: str = Depends(named_actor)) -> dict:
    return service.verify(db, incident_id, workflow_id, data, actor)


@router.post(PREFIX + "/{workflow_id}/escalate")
def escalate(incident_id: str, workflow_id: str, data: EscalationInput, request: Request,
             db: Session = Depends(get_db), actor: str = Depends(named_actor)) -> dict:
    return service.escalate(db, incident_id, workflow_id, data, actor, set(request.app.state.settings.analyst_token_hashes))


@router.post(PREFIX + "/{workflow_id}/acknowledge")
def acknowledge(incident_id: str, workflow_id: str, data: DecisionInput,
                db: Session = Depends(get_db), actor: str = Depends(named_actor)) -> dict:
    return service.acknowledge(db, incident_id, workflow_id, data, actor)


@router.post(PREFIX + "/{workflow_id}/rebaseline")
def rebaseline(incident_id: str, workflow_id: str, data: RebaselineInput,
               db: Session = Depends(get_db), actor: str = Depends(named_actor)) -> dict:
    return service.rebaseline(db, incident_id, workflow_id, data, actor)


@router.post("/incidents/{incident_id}/close-verified-recovery")
def close(incident_id: str, data: DecisionInput, db: Session = Depends(get_db),
          actor: str = Depends(named_actor)) -> dict:
    incident = service._incident(db, incident_id)
    if incident.status in {"resolved", "dismissed"}:
        service.fail("Incident is already closed; no new recovery closure was recorded")
    service.assert_closure(db, incident, require_workflow=True)
    # Expected revision belongs to the catalogued workflow total: prevents closing
    # a stale multi-workflow screen after a rebaseline or new stage was recorded.
    cases = service.list_workflows(db, incident_id)["items"]
    if sum(c["revision"] for c in cases) != data.expected_revision:
        service.fail("Recovery changed since it was read; reload before closing")
    service.record_audit(db, actor_type="analyst", actor_id=actor, action="verified_recovery_closure_requested",
                         resource_type="incident", resource_id=incident_id, incident_id=incident_id,
                         details={"note": data.note, "workflow_ids": [c["workflow_id"] for c in cases],
                                  "verification_kind": "independent_human_attestation", "endpoint_action_executed": False})
    updated = update_incident(db, incident, IncidentPatch(status="resolved"), actor_id=actor)
    return incident_to_detail(db, updated)
