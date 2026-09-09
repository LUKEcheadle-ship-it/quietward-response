from __future__ import annotations

from datetime import datetime, timezone

from app.database.models import ActionRecord, AgentRecord, HostRecord, IncidentRecord
from app.services.policy_service import _evidence_handle_is_bound_to_incident


def _incident(incident_id: str, host_id: str) -> IncidentRecord:
    now = datetime.now(timezone.utc)
    return IncidentRecord(
        incident_id=incident_id,
        title="Synthetic evidence-bound policy incident",
        status="investigating",
        severity="high",
        confidence=0.9,
        affected_hosts=[host_id],
        created_at=now,
        updated_at=now,
        first_event_at=now,
        last_event_at=now,
        event_count=1,
        probable_cause="test",
        correlation_reasons=[],
        recommended_actions=[],
    )


def test_process_handle_must_come_from_successful_triage_for_same_incident_host_agent(client) -> None:
    host_id = "evidence-host"
    agent_id = "evidence-agent"
    handle = "qwrp-" + "a" * 32
    now = datetime.now(timezone.utc)

    with client.app.state.database.session_factory() as session:
        session.add(
            HostRecord(
                host_id=host_id,
                hostname="evidence-host.test",
                operating_system="Linux",
                agent="quietward-response",
                agent_version="1.1.0a1",
                first_seen=now,
                last_seen=now,
                status="reporting",
            )
        )
        session.add(
            AgentRecord(
                agent_id=agent_id,
                host_id=host_id,
                display_name="Evidence test agent",
                key_id="evidence-key",
                hmac_key_b64="dGVzdC1rZXk=",
                created_at=now,
                last_seen=now,
                enabled=True,
                agent_version="1.1.0a1",
            )
        )
        session.add(_incident("incident-one", host_id))
        session.add(_incident("incident-two", host_id))
        session.flush()

        triage = ActionRecord(
            action_id="triage-action",
            incident_id="incident-one",
            target_agent_id=agent_id,
            target_host_id=host_id,
            action_type="collect_incident_triage_bundle",
            parameters={},
            requested_at=now,
            requested_by="analyst",
            expires_at=now,
            status="succeeded",
            policy_allowed=True,
            policy_reasons=[],
            result={
                "components": {
                    "process": {
                        "processes": [
                            {
                                "pid": 4242,
                                "parent_pid": 100,
                                "image": "suspicious.exe",
                                "evidence_handle": handle,
                            }
                        ]
                    }
                }
            },
        )
        session.add(triage)
        session.flush()

        matching = ActionRecord(
            action_id="containment-matching",
            incident_id="incident-one",
            target_agent_id=agent_id,
            target_host_id=host_id,
            action_type="terminate_evidence_process",
            parameters={"evidence_handle": handle},
            requested_at=now,
            requested_by="analyst",
            expires_at=now,
            status="pending",
            policy_reasons=[],
        )
        cross_incident = ActionRecord(
            action_id="containment-cross-incident",
            incident_id="incident-two",
            target_agent_id=agent_id,
            target_host_id=host_id,
            action_type="terminate_evidence_process",
            parameters={"evidence_handle": handle},
            requested_at=now,
            requested_by="analyst",
            expires_at=now,
            status="pending",
            policy_reasons=[],
        )
        unknown_handle = ActionRecord(
            action_id="containment-unknown",
            incident_id="incident-one",
            target_agent_id=agent_id,
            target_host_id=host_id,
            action_type="terminate_evidence_process",
            parameters={"evidence_handle": "qwrp-" + "b" * 32},
            requested_at=now,
            requested_by="analyst",
            expires_at=now,
            status="pending",
            policy_reasons=[],
        )

        assert _evidence_handle_is_bound_to_incident(session, matching) is True
        assert _evidence_handle_is_bound_to_incident(session, cross_incident) is False
        assert _evidence_handle_is_bound_to_incident(session, unknown_handle) is False


def test_failed_triage_result_cannot_authorize_process_containment(client) -> None:
    host_id = "failed-evidence-host"
    agent_id = "failed-evidence-agent"
    handle = "qwrp-" + "c" * 32
    now = datetime.now(timezone.utc)

    with client.app.state.database.session_factory() as session:
        session.add(
            HostRecord(
                host_id=host_id,
                hostname="failed-evidence-host.test",
                operating_system="Linux",
                agent="quietward-response",
                agent_version="1.1.0a1",
                first_seen=now,
                last_seen=now,
                status="reporting",
            )
        )
        session.add(
            AgentRecord(
                agent_id=agent_id,
                host_id=host_id,
                display_name="Failed evidence test agent",
                key_id="failed-evidence-key",
                hmac_key_b64="dGVzdC1rZXk=",
                created_at=now,
                last_seen=now,
                enabled=True,
                agent_version="1.1.0a1",
            )
        )
        session.add(_incident("failed-incident", host_id))
        session.flush()
        session.add(
            ActionRecord(
                action_id="failed-triage",
                incident_id="failed-incident",
                target_agent_id=agent_id,
                target_host_id=host_id,
                action_type="collect_incident_triage_bundle",
                parameters={},
                requested_at=now,
                requested_by="analyst",
                expires_at=now,
                status="failed",
                policy_allowed=True,
                policy_reasons=[],
                result={
                    "components": {
                        "process": {"processes": [{"evidence_handle": handle}]}
                    }
                },
            )
        )
        session.flush()

        containment = ActionRecord(
            action_id="containment-after-failed-triage",
            incident_id="failed-incident",
            target_agent_id=agent_id,
            target_host_id=host_id,
            action_type="terminate_evidence_process",
            parameters={"evidence_handle": handle},
            requested_at=now,
            requested_by="analyst",
            expires_at=now,
            status="pending",
            policy_reasons=[],
        )
        assert _evidence_handle_is_bound_to_incident(session, containment) is False
