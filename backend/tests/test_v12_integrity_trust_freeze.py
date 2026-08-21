from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.database.models import (
    ActionRecord,
    AgentRecord,
    ApprovalRecord,
    EventRecord,
    HostRecord,
    IncidentRecord,
)
from app.services.policy_service import INTEGRITY_TRUST_REASON, evaluate_action_policy


def _recommendation(action_type: str) -> dict[str, object]:
    return {
        "action_type": "diagnostic" if action_type.startswith("collect_") else "remediation",
        "title": action_type,
        "description": action_type,
        "enabled": True,
        "phase": "v1.2 — approval required",
        "registry_action_type": action_type,
        "requires_approval": True,
    }


def _approved_action(
    *,
    incident_id: str,
    agent_id: str,
    host_id: str,
    action_type: str,
    parameters: dict[str, object],
    suffix: str,
    now: datetime,
) -> tuple[ActionRecord, ApprovalRecord]:
    action_id = f"00000000-0000-0000-0000-{suffix:0>12}"
    approval_id = f"10000000-0000-0000-0000-{suffix:0>12}"
    action = ActionRecord(
        action_id=action_id,
        incident_id=incident_id,
        target_agent_id=agent_id,
        target_host_id=host_id,
        action_type=action_type,
        parameters=parameters,
        requested_at=now,
        requested_by="responder-test",
        approval_id=approval_id,
        expires_at=now + timedelta(minutes=3),
        status="approved",
        policy_allowed=None,
        policy_reasons=[],
    )
    approval = ApprovalRecord(
        approval_id=approval_id,
        incident_id=incident_id,
        action_id=action_id,
        requested_by="responder-test",
        requested_at=now,
        status="approved",
        approved_by="responder-test",
        approved_at=now,
        expires_at=now + timedelta(minutes=3),
    )
    return action, approval


def test_integrity_compromise_blocks_mutation_but_keeps_diagnostics_available(client) -> None:
    now = datetime.now(timezone.utc)
    host_id = "host-integrity-freeze"
    agent_id = "agent-integrity-freeze"
    incident_id = "20000000-0000-0000-0000-000000000001"

    with client.app.state.database.session_factory() as session:
        session.add(
            HostRecord(
                host_id=host_id,
                hostname=host_id,
                operating_system="Linux",
                agent="test-sensor",
                agent_version="1.0",
                first_seen=now,
                last_seen=now,
                status="reporting",
            )
        )
        session.add(
            AgentRecord(
                agent_id=agent_id,
                host_id=host_id,
                display_name="Integrity freeze agent",
                key_id="key-integrity-freeze",
                hmac_key_b64="dGVzdC1rZXk=",
                created_at=now,
                last_seen=now,
                enabled=True,
                agent_version="1.2.0-alpha.1",
                supported_actions=[
                    "collect_host_diagnostic",
                    "terminate_process_by_handle",
                ],
                enabled_actions=[
                    "collect_host_diagnostic",
                    "terminate_process_by_handle",
                ],
                capabilities_updated_at=now,
            )
        )
        session.add(
            IncidentRecord(
                incident_id=incident_id,
                title="Endpoint trust failure",
                status="investigating",
                severity="critical",
                confidence=1.0,
                affected_hosts=[host_id],
                created_at=now,
                updated_at=now,
                first_event_at=now,
                last_event_at=now,
                event_count=1,
                probable_cause="Evidence integrity failed",
                correlation_reasons=["integrity failure"],
                recommended_actions=[
                    _recommendation("collect_host_diagnostic"),
                    _recommendation("terminate_process_by_handle"),
                ],
            )
        )
        session.add(
            EventRecord(
                event_id="30000000-0000-0000-0000-000000000001",
                schema_version="1.0",
                source="test-integrity-sensor",
                source_version="1.0",
                host_id=host_id,
                host_name=host_id,
                occurred_at=now,
                event_type="evidence_integrity_failure",
                category="integrity",
                severity="critical",
                confidence=1.0,
                summary="Evidence chain integrity failed",
                payload={},
                normalized={},
                received_at=now,
                incident_id=incident_id,
            )
        )
        diagnostic, diagnostic_approval = _approved_action(
            incident_id=incident_id,
            agent_id=agent_id,
            host_id=host_id,
            action_type="collect_host_diagnostic",
            parameters={},
            suffix="1",
            now=now,
        )
        termination, termination_approval = _approved_action(
            incident_id=incident_id,
            agent_id=agent_id,
            host_id=host_id,
            action_type="terminate_process_by_handle",
            parameters={"resource_handle": "qwrh1_1234567890abcdef"},
            suffix="2",
            now=now,
        )
        session.add_all(
            [diagnostic, diagnostic_approval, termination, termination_approval]
        )
        session.commit()

        diagnostic_allowed, diagnostic_reasons = evaluate_action_policy(
            session,
            diagnostic,
            now=now,
        )
        assert diagnostic_allowed is True
        assert diagnostic_reasons == []

        mutation_allowed, mutation_reasons = evaluate_action_policy(
            session,
            termination,
            now=now,
        )
        assert mutation_allowed is False
        assert mutation_reasons == [INTEGRITY_TRUST_REASON]
