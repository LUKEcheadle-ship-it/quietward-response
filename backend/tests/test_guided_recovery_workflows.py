from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.database.models import ActionRecord, AuditRecord, EventRecord, IncidentRecord
from app.database.resolutions import ResolutionRecord
from app.services.resolution_playbooks import PLAYBOOKS, SOURCE_CATEGORIES

TOKENS = {actor: (actor + "-synthetic-workflow-test-credential-") * 2 for actor in ("operator", "approver", "reviewer")}
NOTE = "Synthetic reviewed recovery evidence with an explicit scoped outcome."


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def headers(actor="operator") -> dict:
    return {"Authorization": "Bearer " + TOKENS[actor]}


@pytest.fixture
def named(client):
    client.app.state.settings = client.app.state.settings.model_copy(update={
        "analyst_token_hashes": {actor: sha(token) for actor, token in TOKENS.items()},
    })
    return client


def incident(client, event_factory, category="identity", index=0, host="host-alpha"):
    response = client.post("/api/v1/events", json=event_factory(index, category=category, host_id=host), headers=headers())
    assert response.status_code == 201, response.text
    return response.json()["incident_id"]


def plan(category="identity", host="host-alpha", family=None):
    return {"host_id": host, "source_category": category, "family": family or ("identity" if category == "security" else category),
            "baseline_sha256": sha("baseline"), "baseline_summary": NOTE, "ticket_reference": "SYNTHETIC-123",
            "rollback_plan": "Use the authorized owner-reviewed rollback and preserve the original evidence."}


def start(client, incident_id, category="identity", **kwargs):
    result = client.post(f"/api/v1/incidents/{incident_id}/resolution-workflows", json=plan(category, **kwargs), headers=headers())
    assert result.status_code == 201, result.text
    return result.json()


def post(client, case, operation, actor="operator", **extra):
    return client.post(f"/api/v1/incidents/{case['incident_id']}/resolution-workflows/{case['workflow_id']}/{operation}",
                       json={"expected_revision": case["revision"], "note": NOTE, **extra}, headers=headers(actor))


def approve(client, case):
    result = post(client, case, "approve", "approver")
    assert result.status_code == 200, result.text
    return result.json()


def steps(client, case):
    for index, checkpoint in enumerate(PLAYBOOKS[case["family"]].checkpoints):
        result = post(client, case, "checkpoints", checkpoint=checkpoint.key,
                      artifact_sha256=sha(f"checkpoint-{index}"), artifact_reference=f"EVIDENCE-{index}", observed_at=now())
        assert result.status_code == 200, result.text
        case = result.json()
    return case


def verify(client, case):
    result = post(client, case, "verify", "reviewer", artifact_sha256=sha("fresh-verification"),
                  artifact_reference="VERIFICATION-123", observed_at=now())
    assert result.status_code == 200, result.text
    return result.json()


@pytest.mark.parametrize("category", sorted(SOURCE_CATEGORIES))
def test_full_category_recovery_has_independent_evidence_and_audit(named, event_factory, category):
    identifier = incident(named, event_factory, category)
    case = start(named, identifier, category)
    assert case["state"] == "awaiting_approval"
    assert case["mode"] == "human_executed_evidence_attested"
    assert not case["endpoint_action_executed"] and not case["artifact_content_verified_by_server"]
    assert post(named, case, "approve").status_code == 403
    assert named.patch(f"/api/v1/incidents/{identifier}", json={"status": "resolved"}, headers=headers()).status_code == 409
    case = approve(named, case)
    case = steps(named, case)
    assert case["state"] == "awaiting_verification"
    case = verify(named, case)
    assert case["state"] == "verified" and case["verifier"] == "reviewer"
    result = named.post(f"/api/v1/incidents/{identifier}/close-verified-recovery",
                        json={"expected_revision": case["revision"], "note": NOTE}, headers=headers())
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "resolved"
    with named.app.state.database.session_factory() as db:
        assert list(db.scalars(select(ActionRecord))) == []
    audit = named.get("/api/v1/audit/verify", headers=headers())
    assert audit.status_code == 200 and audit.json()["valid"] is True
    detail = named.get(f"/api/v1/incidents/{identifier}", headers=headers()).json()
    events = [row for row in detail["audit_trail"] if row["resource_type"] == "resolution_workflow"]
    assert len(events) == 7
    assert all(row["details"]["endpoint_action_executed"] is False for row in events)
    if category == "security":
        assert case["source_category"] == "security" and case["family"] == "identity"


@pytest.mark.parametrize("category", sorted(SOURCE_CATEGORIES))
def test_category_escalation_requires_named_ack_and_does_not_claim_resolution(named, event_factory, category):
    identifier = incident(named, event_factory, category)
    case = start(named, identifier, category)
    response = post(named, case, "escalate", assigned_to="reviewer", ticket_reference="EXTERNAL-456",
                    due_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat())
    assert response.status_code == 200, response.text
    case = response.json()
    assert case["state"] == "escalated"
    assert case["escalation"]["external_ticket_created_by_server"] is False
    assert post(named, case, "acknowledge", "approver").status_code == 403
    response = post(named, case, "acknowledge", "reviewer")
    assert response.status_code == 200
    case = response.json()
    assert case["escalation"]["acknowledged_by"] == "reviewer"
    assert named.patch(f"/api/v1/incidents/{identifier}", json={"status": "resolved"}, headers=headers()).status_code == 409
    assert named.get(f"/api/v1/incidents/{identifier}", headers=headers()).json()["status"] == "investigating"


def test_unauthenticated_and_demo_writes_rejected(client, event_factory):
    identifier = incident(client, event_factory)
    url = f"/api/v1/incidents/{identifier}/resolution-workflows"
    assert client.post(url, json=plan()).status_code == 403
    client.app.state.settings = client.app.state.settings.model_copy(update={"analyst_token_hashes": {"operator": sha(TOKENS["operator"])}})
    assert client.post(url, json=plan()).status_code == 401
    assert client.get(url).status_code == 401


def test_forged_actor_header_cannot_self_approve(named, event_factory):
    case = start(named, incident(named, event_factory))
    response = named.post(f"/api/v1/incidents/{case['incident_id']}/resolution-workflows/{case['workflow_id']}/approve",
                          json={"expected_revision": case["revision"], "note": NOTE},
                          headers=headers() | {"X-Actor-ID": "reviewer"})
    assert response.status_code == 403


@pytest.mark.parametrize("changes", [{"host_id": "unrelated-host"}, {"source_category": "container", "family": "container"},
                                    {"family": "security"}, {"family": "container"}, {"family": "arbitrary"}])
def test_unbound_scope_or_unclassified_family_rejected(named, event_factory, changes):
    identifier = incident(named, event_factory)
    response = named.post(f"/api/v1/incidents/{identifier}/resolution-workflows", json=plan() | changes, headers=headers())
    assert response.status_code == 422


def test_unknown_source_must_route_to_concrete_family(named, event_factory):
    identifier = incident(named, event_factory, "custom-family")
    case = start(named, identifier, "security", family="operational")
    assert case["source_category"] == "security" and case["family"] == "operational"


@pytest.mark.parametrize("changes", [{"command": "do not execute"}, {"baseline_sha256": "bad"}, {"baseline_summary": " " * 60},
                                    {"rollback_plan": ""}, {"ticket_reference": "\u0000secret"}])
def test_invalid_plan_metadata_rejected(named, event_factory, changes):
    identifier = incident(named, event_factory)
    assert named.post(f"/api/v1/incidents/{identifier}/resolution-workflows", json=plan() | changes, headers=headers()).status_code == 422


def test_duplicate_and_cross_incident_reference_rejected(named, event_factory):
    first = incident(named, event_factory)
    second = incident(named, event_factory, index=20, host="other-host")
    case = start(named, first)
    assert named.post(f"/api/v1/incidents/{first}/resolution-workflows", json=plan(), headers=headers()).status_code == 409
    case["incident_id"] = second
    assert post(named, case, "approve", "approver").status_code == 404


def test_stale_revision_does_not_repeat_approval_or_audit(named, event_factory):
    case = start(named, incident(named, event_factory))
    approved = approve(named, case)
    before = named.get("/api/v1/audit/verify", headers=headers()).json()
    assert post(named, case, "approve", "approver").status_code == 409
    assert named.get("/api/v1/audit/verify", headers=headers()).json() == before
    assert approved["revision"] == case["revision"] + 1


@pytest.mark.parametrize("kind", ["before_approval", "out_of_order", "skip_required", "wrong_operator", "stale", "future", "naive", "bad_revision"])
def test_checkpoint_preconditions_are_enforced(named, event_factory, kind):
    case = start(named, incident(named, event_factory))
    if kind != "before_approval": case = approve(named, case)
    values = {"checkpoint": "identify", "artifact_sha256": sha("step"), "artifact_reference": "EVIDENCE-123", "observed_at": now()}
    actor = "operator"
    if kind == "out_of_order": values["checkpoint"] = "recover"
    if kind == "skip_required": values["outcome"] = "not_applicable"
    if kind == "wrong_operator": actor = "approver"
    if kind == "stale": values["observed_at"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    if kind == "future": values["observed_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    if kind == "naive": values["observed_at"] = "2026-01-01T12:00:00"
    if kind == "bad_revision": values["expected_revision"] = True
    assert post(named, case, "checkpoints", actor, **values).status_code in {403, 409, 422}


def test_only_explicitly_conditional_checkpoint_allows_not_applicable(named, event_factory):
    case = approve(named, start(named, incident(named, event_factory, "malware"), "malware"))
    for checkpoint in PLAYBOOKS["malware"].checkpoints:
        result = post(named, case, "checkpoints", checkpoint=checkpoint.key, outcome="not_applicable" if checkpoint.conditional else "done",
                      artifact_sha256=sha(checkpoint.key), artifact_reference="EVIDENCE-123", observed_at=now())
        assert result.status_code == 200, result.text
        case = result.json()
    assert case["state"] == "awaiting_verification"


@pytest.mark.parametrize("kind", ["same_operator", "baseline_reused", "checkpoint_reused", "before_steps", "stale"])
def test_independent_fresh_verification_required(named, event_factory, kind):
    case = approve(named, start(named, incident(named, event_factory)))
    if kind != "before_steps": case = steps(named, case)
    actor = "operator" if kind == "same_operator" else "reviewer"
    digest = sha("baseline") if kind == "baseline_reused" else sha("checkpoint-0") if kind == "checkpoint_reused" else sha("new-verification")
    observed = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat() if kind == "stale" else now()
    assert post(named, case, "verify", actor, artifact_sha256=digest, artifact_reference="VERIFY-123", observed_at=observed).status_code in {403, 409, 422}


def test_new_incident_evidence_requires_rebaseline_and_fresh_approval(named, event_factory):
    identifier = incident(named, event_factory)
    case = approve(named, start(named, identifier))
    assert incident(named, event_factory, index=1) == identifier
    assert post(named, case, "checkpoints", checkpoint="identify", artifact_sha256=sha("new"), artifact_reference="EVIDENCE-123", observed_at=now()).status_code == 409
    newplan = {k: v for k, v in plan().items() if k not in {"family", "source_category", "host_id"}}
    newplan.update(baseline_sha256=sha("new-baseline"), expected_revision=case["revision"])
    response = named.post(f"/api/v1/incidents/{identifier}/resolution-workflows/{case['workflow_id']}/rebaseline", json=newplan, headers=headers())
    assert response.status_code == 200, response.text
    current = response.json()
    assert current["approver"] is None and current["checkpoints"] == [] and current["state"] == "awaiting_approval"
    assert current["context_current"] is True


def test_audited_projection_tampering_fails_closed(named, event_factory):
    case = start(named, incident(named, event_factory))
    with named.app.state.database.session_factory() as db:
        row = db.get(ResolutionRecord, case["workflow_id"])
        row.owner = "reviewer"
        db.commit()
    response = named.get(f"/api/v1/incidents/{case['incident_id']}/resolution-workflows", headers=headers())
    assert response.status_code == 409 and "audited history" in response.text


def test_incident_cannot_close_with_other_uncovered_category(named, event_factory):
    identifier = incident(named, event_factory)
    other = incident(named, event_factory, "network", index=1)
    # Fixture for an incident with multiple categories; the ordinary correlator
    # deliberately creates separate incidents for these two simple sample events.
    with named.app.state.database.session_factory() as db:
        for event in db.scalars(select(EventRecord).where(EventRecord.incident_id == other)):
            event.incident_id = identifier
        db.commit()
    case = verify(named, steps(named, approve(named, start(named, identifier))))
    result = named.post(f"/api/v1/incidents/{identifier}/close-verified-recovery", json={"expected_revision": case["revision"], "note": NOTE}, headers=headers())
    assert result.status_code == 409
    assert named.patch(f"/api/v1/incidents/{identifier}", json={"status": "dismissed"}, headers=headers()).status_code == 409


@pytest.mark.parametrize("kind", ["self", "unknown", "past_due", "unbounded_due"])
def test_escalation_requires_accountable_owner_and_due_date(named, event_factory, kind):
    case = start(named, incident(named, event_factory))
    assigned = "operator" if kind == "self" else "unknown" if kind == "unknown" else "reviewer"
    days = -1 if kind == "past_due" else 9 if kind == "unbounded_due" else 1
    result = post(named, case, "escalate", assigned_to=assigned, ticket_reference="EXTERNAL-456", due_at=(datetime.now(timezone.utc) + timedelta(days=days)).isoformat())
    assert result.status_code == 422


def test_catalog_has_concrete_acceptance_criteria_and_no_execution_claim(named):
    result = named.get("/api/v1/resolution-playbooks", headers=headers()).json()
    assert result["actor"] == "operator" and result["named_auth_configured"]
    assert not result["endpoint_execution"] and not result["artifact_contents_verified_by_server"]
    assert len(result["playbooks"]) == 11
    for playbook in result["playbooks"]:
        assert len(playbook["checkpoints"]) == 4 and len(playbook["verification"]) > 60
        assert len(playbook["digest"]) == 64
        assert all(len(s["instruction"]) > 70 and len(s["acceptance"]) > 50 for s in playbook["checkpoints"])


def test_failed_checkpoint_stops_progress_and_cannot_be_verified(named, event_factory):
    case = approve(named, start(named, incident(named, event_factory)))
    result = post(named, case, "checkpoints", checkpoint="identify", outcome="failed",
                  artifact_sha256=sha("failure"), artifact_reference="FAILURE-123", observed_at=now())
    assert result.status_code == 200, result.text
    case = result.json()
    assert case["state"] == "blocked"
    assert post(named, case, "checkpoints", checkpoint="contain", artifact_sha256=sha("next"), artifact_reference="NEXT-123", observed_at=now()).status_code == 409
    assert post(named, case, "verify", "reviewer", artifact_sha256=sha("verification"), artifact_reference="VERIFY-123", observed_at=now()).status_code == 409
    assert post(named, case, "escalate", assigned_to="reviewer", ticket_reference="BLOCKED-123", due_at=(datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()).status_code == 200


def test_new_evidence_invalidates_previously_verified_recovery(named, event_factory):
    identifier = incident(named, event_factory)
    case = verify(named, steps(named, approve(named, start(named, identifier))))
    assert incident(named, event_factory, index=1) == identifier
    result = named.post(f"/api/v1/incidents/{identifier}/close-verified-recovery", json={"expected_revision": case["revision"], "note": NOTE}, headers=headers())
    assert result.status_code == 409 and "evidence changed" in result.text


def test_workflow_audit_tampering_refuses_reads_and_updates(named, event_factory):
    case = start(named, incident(named, event_factory))
    with named.app.state.database.session_factory() as db:
        audit = db.scalars(select(AuditRecord).where(AuditRecord.resource_id == case["workflow_id"])).first()
        audit.details = {"tampered": True}
        db.commit()
    assert post(named, case, "approve", "approver").status_code == 409
    assert named.get(f"/api/v1/incidents/{case['incident_id']}/resolution-workflows", headers=headers()).status_code == 409


def test_database_version_counter_rejects_parallel_projection_update(named, event_factory):
    from sqlalchemy.orm.exc import StaleDataError
    case = start(named, incident(named, event_factory))
    factory = named.app.state.database.session_factory
    with factory() as first, factory() as second:
        one = first.get(ResolutionRecord, case["workflow_id"])
        two = second.get(ResolutionRecord, case["workflow_id"])
        one.state = "first-write"
        first.commit()
        two.state = "stale-write"
        with pytest.raises(StaleDataError):
            second.commit()
        second.rollback()


def test_rebaseline_preserves_old_audit_snapshots(named, event_factory):
    case = approve(named, start(named, incident(named, event_factory)))
    old_revision = case["revision"]
    payload = {k: v for k, v in plan().items() if k not in {"family", "source_category", "host_id"}}
    payload.update(baseline_sha256=sha("updated-baseline"), expected_revision=old_revision)
    result = named.post(f"/api/v1/incidents/{case['incident_id']}/resolution-workflows/{case['workflow_id']}/rebaseline", json=payload, headers=headers())
    assert result.status_code == 200
    with named.app.state.database.session_factory() as db:
        audits = list(db.scalars(select(AuditRecord).where(AuditRecord.resource_id == case["workflow_id"]).order_by(AuditRecord.timestamp)))
        assert [a.details["snapshot"]["revision"] for a in audits] == [1, 2, 3]
        assert audits[1].details["snapshot"]["approver"] == "approver"
        assert audits[2].details["snapshot"]["approver"] is None


def test_complete_multiple_categories_can_close_only_after_both_verified(named, event_factory):
    identifier = incident(named, event_factory)
    other = incident(named, event_factory, "network", index=1)
    with named.app.state.database.session_factory() as db:
        for event in db.scalars(select(EventRecord).where(EventRecord.incident_id == other)):
            event.incident_id = identifier
        db.commit()
    first = verify(named, steps(named, approve(named, start(named, identifier))))
    second = verify(named, steps(named, approve(named, start(named, identifier, "network"))))
    url = f"/api/v1/incidents/{identifier}/close-verified-recovery"
    assert named.post(url, json={"expected_revision": first["revision"], "note": NOTE}, headers=headers()).status_code == 409
    response = named.post(url, json={"expected_revision": first["revision"] + second["revision"], "note": NOTE}, headers=headers())
    assert response.status_code == 200 and response.json()["status"] == "resolved"


def test_security_reroute_requires_new_baseline_and_reapproval(named, event_factory):
    case = approve(named, start(named, incident(named, event_factory, "security"), "security"))
    payload = {k: v for k, v in plan().items() if k not in {"family", "source_category", "host_id"}}
    payload.update(family="file_integrity", baseline_sha256=sha("rerouted-baseline"), expected_revision=case["revision"])
    response = named.post(f"/api/v1/incidents/{case['incident_id']}/resolution-workflows/{case['workflow_id']}/rebaseline", json=payload, headers=headers())
    assert response.status_code == 200, response.text
    assert response.json()["family"] == "file_integrity" and response.json()["state"] == "awaiting_approval"
