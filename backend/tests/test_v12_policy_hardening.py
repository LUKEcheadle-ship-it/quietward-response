from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.database.models import AgentRecord, EventRecord, HostRecord, IncidentRecord
from app.services.policy_service import (
    AGENT_CAPABILITY_DISABLED_REASON,
    AGENT_CAPABILITY_MISSING_REASON,
    AGENT_CAPABILITY_STALE_REASON,
    agent_capability_reason,
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
