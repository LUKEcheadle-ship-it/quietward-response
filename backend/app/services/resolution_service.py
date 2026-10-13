"""Accountable, evidence-attested human recovery; no endpoint execution surface."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from app.database.models import ActionRecord, AuditRecord, EventRecord, IncidentRecord, utcnow
from app.database.resolutions import ResolutionRecord
from app.schemas.resolution import (
    CheckpointInput, DecisionInput, EscalationInput, RebaselineInput, VerificationInput, WorkflowCreate,
)
from app.services.audit_service import record_audit, verify_audit_chain
from app.services.resolution_playbooks import PLAYBOOKS, SOURCE_CATEGORIES

MODE = "human_executed_evidence_attested"
_ACTIVE_ACTIONS = {"pending", "approved", "dispatching", "executing"}


def fail(message: str, status: int = 409) -> None:
    raise HTTPException(status_code=status, detail=message)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _events(session: Session, incident_id: str, host_id: str | None = None) -> list[EventRecord]:
    statement = select(EventRecord).where(EventRecord.incident_id == incident_id)
    if host_id is not None:
        statement = statement.where(EventRecord.host_id == host_id)
    return list(session.scalars(statement.order_by(EventRecord.event_id)))


def _source(event: EventRecord) -> str:
    return event.category if event.category in SOURCE_CATEGORIES else "security"


def _context(events: list[EventRecord]) -> str:
    return _digest([{"event_id": e.event_id, "host_id": e.host_id, "category": e.category,
                     "payload": e.payload, "normalized": e.normalized} for e in events])


def _incident(session: Session, incident_id: str) -> IncidentRecord:
    incident = session.get(IncidentRecord, incident_id)
    if incident is None:
        fail("Incident not found", 404)
    return incident


def _snapshot(case: ResolutionRecord) -> dict[str, Any]:
    return {name: (_utc(value).isoformat() if isinstance(value, datetime) else value)
            for name in ("workflow_id", "incident_id", "host_id", "source_category", "family", "state", "revision", "owner",
                         "approver", "verifier", "created_at", "updated_at", "approved_at", "context_digest", "playbook_digest",
                         "plan", "checkpoints", "verification", "escalation")
            for value in [getattr(case, name)]}


def _audit_intact(session: Session) -> None:
    if verify_audit_chain(session)["valid"] is not True:
        fail("Audit integrity failed; preserve the evidence and use the documented recovery process")


def _record_intact(session: Session, case: ResolutionRecord) -> None:
    audit = session.scalars(select(AuditRecord).where(
        AuditRecord.resource_type == "resolution_workflow", AuditRecord.resource_id == case.workflow_id,
    ).order_by(AuditRecord.timestamp.desc(), AuditRecord.audit_id.desc()).limit(1)).first()
    if audit is None or (audit.details or {}).get("snapshot") != _snapshot(case):
        fail("Resolution state does not match its audited history; preserve evidence and investigate")


def _fresh(session: Session, case: ResolutionRecord) -> None:
    if case.family not in PLAYBOOKS or PLAYBOOKS[case.family].digest() != case.playbook_digest:
        fail("Recovery playbook changed; rebaseline and obtain a new approval")
    if _context(_events(session, case.incident_id, case.host_id)) != case.context_digest:
        fail("Incident evidence changed; rebaseline and obtain a new approval")


def _get(session: Session, incident_id: str, workflow_id: str, revision: int | None = None) -> ResolutionRecord:
    _incident(session, incident_id)
    case = session.get(ResolutionRecord, workflow_id)
    if case is None or case.incident_id != incident_id:
        fail("Resolution workflow not found in this incident", 404)
    _audit_intact(session)
    _record_intact(session, case)
    if revision is not None and case.revision != revision:
        fail("Resolution changed since it was read; reload before submitting")
    return case


def _owner(case: ResolutionRecord, actor: str) -> None:
    if case.owner != actor:
        fail("Only the assigned operator can record recovery work", 403)


def _open_incident(session: Session, case: ResolutionRecord) -> None:
    if _incident(session, case.incident_id).status in {"resolved", "dismissed"}:
        fail("Reopen the incident before changing a recovery workflow")


def _commit(session: Session, case: ResolutionRecord, actor: str, action: str, note: str = "") -> dict:
    if action != "resolution_started":
        case.updated_at = utcnow()
    try:
        session.flush()  # ORM version counter checks a stale row before auditing it.
        record_audit(session, actor_type="analyst", actor_id=actor, action=action,
                     resource_type="resolution_workflow", resource_id=case.workflow_id,
                     incident_id=case.incident_id,
                     details={"mode": MODE, "note": note, "snapshot": _snapshot(case),
                              "endpoint_action_executed": False, "artifact_content_verified_by_server": False})
        session.commit()
    except (StaleDataError, IntegrityError) as exc:
        session.rollback()
        raise HTTPException(409, "Resolution scope/revision changed; reload before submitting") from exc
    session.refresh(case)
    return present(session, case)


def present(session: Session, case: ResolutionRecord) -> dict:
    result = _snapshot(case)
    result.update(mode=MODE, endpoint_action_executed=False, artifact_content_verified_by_server=False,
                  context_current=_context(_events(session, case.incident_id, case.host_id)) == case.context_digest,
                  playbook_current=case.family in PLAYBOOKS and PLAYBOOKS[case.family].digest() == case.playbook_digest)
    return result


def list_workflows(session: Session, incident_id: str) -> dict:
    _incident(session, incident_id)
    _audit_intact(session)
    cases = list(session.scalars(select(ResolutionRecord).where(ResolutionRecord.incident_id == incident_id)
                               .order_by(ResolutionRecord.created_at)))
    for case in cases:
        _record_intact(session, case)
    scopes = sorted({(e.host_id, _source(e)) for e in _events(session, incident_id)})
    return {"items": [present(session, c) for c in cases],
            "required_scopes": [{"host_id": host, "source_category": category} for host, category in scopes]}


def start(session: Session, incident_id: str, data: WorkflowCreate, actor: str) -> dict:
    incident = _incident(session, incident_id)
    if incident.status in {"resolved", "dismissed"}:
        fail("Reopen the incident before starting recovery")
    _audit_intact(session)
    if data.source_category not in SOURCE_CATEGORIES or data.family not in PLAYBOOKS:
        fail("Choose a supported source category and a concrete recovery family", 422)
    if data.source_category != "security" and data.source_category != data.family:
        fail("A classified finding must use its own recovery family", 422)
    events = _events(session, incident_id, data.host_id)
    if not events or not any(_source(e) == data.source_category for e in events):
        fail("Recovery scope must come from this incident's actual host/event evidence", 422)
    if session.scalar(select(ResolutionRecord.workflow_id).where(
        ResolutionRecord.incident_id == incident_id, ResolutionRecord.host_id == data.host_id,
        ResolutionRecord.source_category == data.source_category,
    )):
        fail("This recovery scope already exists; use its rebaseline operation")
    case = ResolutionRecord(incident_id=incident_id, host_id=data.host_id, source_category=data.source_category,
                            family=data.family, owner=actor, state="awaiting_approval", revision=1,
                            plan=data.model_dump(exclude={"host_id", "source_category", "family"}),
                            checkpoints=[], context_digest=_context(events), playbook_digest=PLAYBOOKS[data.family].digest())
    session.add(case)
    if incident.status == "new":
        incident.status = "investigating"
        incident.updated_at = utcnow()
        record_audit(session, actor_type="analyst", actor_id=actor, action="incident_status_changed",
                     resource_type="incident", resource_id=incident_id, incident_id=incident_id,
                     details={"previous": "new", "current": "investigating", "reason": "guided_recovery_started"})
    return _commit(session, case, actor, "resolution_started")


def approve(session: Session, incident_id: str, workflow_id: str, data: DecisionInput, actor: str) -> dict:
    case = _get(session, incident_id, workflow_id, data.expected_revision)
    _open_incident(session, case)
    _fresh(session, case)
    if case.state != "awaiting_approval":
        fail("Recovery is not awaiting approval")
    if actor == case.owner:
        fail("A different authenticated analyst must approve the operator's plan", 403)
    case.state, case.approver, case.approved_at = "approved", actor, utcnow()
    return _commit(session, case, actor, "resolution_plan_approved", data.note)


def _observed(value: datetime, not_before: datetime) -> str:
    now = utcnow()
    if value > now + timedelta(seconds=5) or value < _utc(not_before):
        fail("Evidence must be newly observed after this workflow stage, not future-dated or stale", 422)
    return _utc(value).isoformat()


def checkpoint(session: Session, incident_id: str, workflow_id: str, data: CheckpointInput, actor: str) -> dict:
    case = _get(session, incident_id, workflow_id, data.expected_revision)
    _owner(case, actor)
    _open_incident(session, case)
    _fresh(session, case)
    if case.state not in {"approved", "in_progress"} or case.approved_at is None:
        fail("An approved active recovery plan is required")
    steps = PLAYBOOKS[case.family].checkpoints
    index = len(case.checkpoints)
    if index >= len(steps) or data.checkpoint != steps[index].key:
        fail("Complete the next required checkpoint in order")
    if data.outcome == "not_applicable" and not steps[index].conditional:
        fail("This recovery checkpoint cannot be skipped", 422)
    not_before = datetime.fromisoformat(case.checkpoints[-1]["recorded_at"]) if case.checkpoints else case.approved_at
    evidence = data.model_dump(mode="json", exclude={"expected_revision"})
    evidence.update(observed_at=_observed(data.observed_at, not_before), actor=actor, recorded_at=utcnow().isoformat())
    case.checkpoints = [*case.checkpoints, evidence]
    case.state = ("blocked" if data.outcome == "failed" else
                  "awaiting_verification" if len(case.checkpoints) == len(steps) else "in_progress")
    return _commit(session, case, actor, "resolution_checkpoint_recorded")


def verify(session: Session, incident_id: str, workflow_id: str, data: VerificationInput, actor: str) -> dict:
    case = _get(session, incident_id, workflow_id, data.expected_revision)
    _open_incident(session, case)
    _fresh(session, case)
    if actor == case.owner:
        fail("A different authenticated analyst must independently verify recovery", 403)
    if case.state != "awaiting_verification" or len(case.checkpoints) != len(PLAYBOOKS[case.family].checkpoints):
        fail("Every required recovery checkpoint must be completed before verification")
    used = {case.plan["baseline_sha256"], *(item["artifact_sha256"] for item in case.checkpoints)}
    if data.artifact_sha256 in used:
        fail("Independent verification requires a new post-recovery evidence artifact", 422)
    evidence = data.model_dump(mode="json", exclude={"expected_revision"})
    evidence["observed_at"] = _observed(data.observed_at, datetime.fromisoformat(case.checkpoints[-1]["recorded_at"]))
    evidence.update(actor=actor, verified_at=utcnow().isoformat(),
                    verification_kind="independent_human_attestation", endpoint_state_verified_by_server=False)
    case.verification, case.verifier, case.state = evidence, actor, "verified"
    return _commit(session, case, actor, "resolution_independently_verified")


def escalate(session: Session, incident_id: str, workflow_id: str, data: EscalationInput, actor: str,
             known_analysts: set[str]) -> dict:
    case = _get(session, incident_id, workflow_id, data.expected_revision)
    _owner(case, actor)
    _open_incident(session, case)
    if case.state in {"verified", "escalated"}:
        fail("Verified or already escalated recovery cannot be escalated again")
    if data.assigned_to not in known_analysts or data.assigned_to == actor:
        fail("Escalation requires a different configured, named analyst", 422)
    if not utcnow() < data.due_at <= utcnow() + timedelta(days=7):
        fail("Escalation must have an explicit follow-up within seven days", 422)
    case.escalation = data.model_dump(mode="json", exclude={"expected_revision"}) | {
        "created_by": actor, "created_at": utcnow().isoformat(), "acknowledged_by": None,
        "external_ticket_created_by_server": False,
    }
    case.state = "escalated"
    return _commit(session, case, actor, "resolution_escalated")


def acknowledge(session: Session, incident_id: str, workflow_id: str, data: DecisionInput, actor: str) -> dict:
    case = _get(session, incident_id, workflow_id, data.expected_revision)
    _open_incident(session, case)
    if case.state != "escalated" or not case.escalation or case.escalation.get("acknowledged_by"):
        fail("An unacknowledged escalation is required")
    if actor != case.escalation["assigned_to"]:
        fail("Only the assigned named analyst can acknowledge this escalation", 403)
    case.escalation = case.escalation | {"acknowledged_by": actor, "acknowledged_at": utcnow().isoformat(), "acknowledgement": data.note}
    return _commit(session, case, actor, "resolution_escalation_acknowledged")


def rebaseline(session: Session, incident_id: str, workflow_id: str, data: RebaselineInput, actor: str) -> dict:
    case = _get(session, incident_id, workflow_id, data.expected_revision)
    _owner(case, actor)
    _open_incident(session, case)
    if data.baseline_sha256 == case.plan["baseline_sha256"]:
        fail("A new baseline evidence artifact is required for reapproval", 422)
    if data.family is not None:
        if data.family not in PLAYBOOKS or (case.source_category != "security" and data.family != case.source_category):
            fail("Only unclassified security findings may be rerouted to a different concrete family", 422)
        case.family = data.family
    case.plan = data.model_dump(exclude={"expected_revision", "family"})
    case.context_digest = _context(_events(session, incident_id, case.host_id))
    case.playbook_digest = PLAYBOOKS[case.family].digest()
    case.state, case.approver, case.verifier, case.approved_at = "awaiting_approval", None, None, None
    case.checkpoints, case.verification, case.escalation = [], None, None
    return _commit(session, case, actor, "resolution_rebaselined", "Prior approvals and work remain in immutable audit snapshots; fresh approval is required.")


def assert_closure(session: Session, incident: IncidentRecord, *, require_workflow: bool = False) -> None:
    cases = list(session.scalars(select(ResolutionRecord).where(ResolutionRecord.incident_id == incident.incident_id)))
    if not cases and not require_workflow:
        return  # Preserve legacy manual status labels; they are not verified workflow outcomes.
    _audit_intact(session)
    needed = {(e.host_id, _source(e)) for e in _events(session, incident.incident_id)}
    by_scope = {(c.host_id, c.source_category): c for c in cases}
    if not needed or set(by_scope) != needed:
        fail("Every affected host/finding category requires its own verified recovery workflow")
    for case in cases:
        _record_intact(session, case)
        _fresh(session, case)
        if case.state != "verified" or not case.verification or not case.verifier or case.verifier == case.owner:
            fail("Unverified or escalated recovery cannot be closed as resolved")
    active = session.scalar(select(ActionRecord.action_id).where(
        ActionRecord.incident_id == incident.incident_id, ActionRecord.status.in_(_ACTIVE_ACTIONS),
    ).limit(1))
    if active:
        fail("Finish or explicitly cancel pending endpoint actions before closing recovery")
