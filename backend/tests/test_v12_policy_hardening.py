from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.database.models import (
    ActionRecord,
    AgentRecord,
    ApprovalRecord,
    EventRecord,
    HostRecord,
    IncidentRecord,
)
from app.schemas.action import ActionCreate
from app.services.action_service import ActionError, create_action
from app.services.policy_service import (
    AGENT_CAPABILITY_DISABLED_REASON,
    AGENT_CAPABILITY_MISSING_REASON,
    AGENT_CAPABILITY_STALE_REASON,
    TARGET_HOST_MISSING_REASON,
    agent_capability_reason,
    evaluate_action_policy,
    incident_integrity_compromised,
)


def _agent(*, updated_at, enabled_actions: list[str]) -> AgentRecord:
    return AgentRecord(
        agent_id=str(uuid4()),
        host_id="host-policy-hardening",
        display_name="policy-hardening-agent",
        key_id=str(uuid4()),
        hmac_key_b64="dGVzdA==",
        created_at=datetime.now(timezone.utc),
        last_seen=None,
        enabled=True,
        agent_version="1.2.0-alpha.1-test",
        supported_actions=["collect_process_diagnostic", "terminate_process_by_handle"],
        enabled_actions=enabled_actions,
        capabilities_updated_at=updated_at,
    )


def test_capability_policy_fails_closed_for_missing_stale_future_and_disabled_reports() -> None:
    now = datetime.now(timezone.utc)

    missing = _agent(updated_at=None, enabled_actions=["collect_process_diagnostic"])
    assert agent_capability_reason(missing, "collect_process_diagnostic", now=now) == (
        AGENT_CAPABILITY_MISSING_REASON
    )

    stale = _agent(
        updated_at=now - timedelta(minutes=16),
        enabled_actions=["collect_process_diagnostic"],
    )
    assert agent_capability_reason(stale, "collect_process_diagnostic", now=now) == (
        AGENT_CAPABILITY_STALE_REASON
    )

    future = _agent(
        updated_at=now + timedelta(seconds=31),
        enabled_actions=["collect_process_diagnostic"],
    )
    assert agent_capability_reason(future, "collect_process_diagnostic", now=now) == (
        AGENT_CAPABILITY_STALE_REASON
    )

    disabled = _agent(updated_at=now, enabled_actions=["collect_process_diagnostic"])
    assert agent_capability_reason(disabled, "terminate_process_by_handle", now=now) == (
        AGENT_CAPABILITY_DISABLED_REASON
    )

    enabled = _agent(
        updated_at=now,
        enabled_actions=["collect_process_diagnostic", "terminate_process_by_handle"],
    )
    assert agent_capability_reason(enabled, "terminate_process_by_handle", now=now) is None

    # The legacy demo action remains exempt for backwards compatibility only.
    assert agent_capability_reason(missing, "restart_quietward_demo_service", now=now) is None


def _missing_host_fixture(session, *, now: datetime) -> tuple[str, str, str]:
    host_id = "host-missing-policy-row"
    incident_id = str(uuid4())
    agent_id = str(uuid4())
    session.add(
        IncidentRecord(
            incident_id=incident_id,
            title="Missing host policy boundary",
            status="new",
            severity="high",
            confidence=1.0,
            affected_hosts=[host_id],
            created_at=now,
            updated_at=now,
            first_event_at=now,
            last_event_at=now,
            event_count=1,
            probable_cause="synthetic policy regression",
            correlation_reasons=[],
            recommended_actions=[
                {
                    "action_type": "diagnostic",
                    "title": "Collect process diagnostic",
                    "description": "Synthetic regression action",
                    "enabled": True,
                    "phase": "v1.2 — approval required",
                    "registry_action_type": "collect_process_diagnostic",
                    "requires_approval": True,
                }
            ],
        )
    )
    session.add(
        AgentRecord(
            agent_id=agent_id,
            host_id=host_id,
            display_name="missing-host-agent",
            key_id=str(uuid4()),
            hmac_key_b64="dGVzdA==",
            created_at=now,
            last_seen=now,
            enabled=True,
            agent_version="1.2.0-alpha.1-test",
            supported_actions=["collect_process_diagnostic"],
            enabled_actions=["collect_process_diagnostic"],
            capabilities_updated_at=now,
        )
    )
    session.commit()
    return host_id, incident_id, agent_id


def test_action_creation_rejects_missing_target_host_record(client) -> None:
    now = datetime.now(timezone.utc)
    with client.app.state.database.session_factory() as session:
        host_id, incident_id, agent_id = _missing_host_fixture(session, now=now)
        with pytest.raises(ActionError, match="target host record does not exist"):
            create_action(
                session,
                incident_id=incident_id,
                payload=ActionCreate(
                    target_agent_id=agent_id,
                    target_host_id=host_id,
                    action_type="collect_process_diagnostic",
                    parameters={},
                ),
                actor_id="policy-tester",
            )
        assert session.query(ActionRecord).filter_by(incident_id=incident_id).count() == 0


def test_action_policy_rejects_missing_target_host_record(client) -> None:
    now = datetime.now(timezone.utc)
    action_id = str(uuid4())
    approval_id = str(uuid4())

    with client.app.state.database.session_factory() as session:
        host_id, incident_id, agent_id = _missing_host_fixture(session, now=now)
        action = ActionRecord(
            action_id=action_id,
            incident_id=incident_id,
            target_agent_id=agent_id,
            target_host_id=host_id,
            action_type="collect_process_diagnostic",
            parameters={},
            requested_at=now,
            requested_by="policy-tester",
            approval_id=approval_id,
            expires_at=now + timedelta(minutes=5),
            status="approved",
        )
        session.add(action)
        session.add(
            ApprovalRecord(
                approval_id=approval_id,
                incident_id=incident_id,
                action_id=action_id,
                requested_by="policy-tester",
                requested_at=now,
                status="approved",
                approved_by="policy-reviewer",
                approved_at=now,
                expires_at=now + timedelta(minutes=5),
            )
        )
        session.commit()

        allowed, reasons = evaluate_action_policy(session, action, now=now)
        assert allowed is False
        assert TARGET_HOST_MISSING_REASON in reasons


def test_integrity_event_freezes_mutating_trust_path(tmp_path, client) -> None:
    now = datetime.now(timezone.utc)
    host_id = "host-integrity-freeze"
    incident_id = str(uuid4())

    with client.app.state.database.session_factory() as session:
        session.add(
            HostRecord(
                host_id=host_id,
                hostname=host_id,
                operating_system="Linux",
                agent="synthetic-test",
                agent_version="1.0",
                first_seen=now,
                last_seen=now,
                status="reporting",
            )
        )
        session.add(
            IncidentRecord(
                incident_id=incident_id,
                title="Integrity trust failure",
                status="new",
                severity="critical",
                confidence=1.0,
                affected_hosts=[host_id],
                created_at=now,
                updated_at=now,
                first_event_at=now,
                last_event_at=now,
                event_count=1,
                probable_cause="sensor integrity failure",
                correlation_reasons=[],
                recommended_actions=[],
            )
        )
        session.add(
            EventRecord(
                event_id=str(uuid4()),
                schema_version="1.0",
                source="synthetic-test",
                source_version="1.0",
                host_id=host_id,
                host_name=host_id,
                occurred_at=now,
                event_type="evidence_integrity_failure",
                category="integrity",
                severity="critical",
                confidence=1.0,
                summary="Synthetic integrity failure",
                payload={},
                normalized={},
                received_at=now,
                incident_id=incident_id,
            )
        )
        session.commit()
        assert incident_integrity_compromised(session, incident_id) is True
