from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select

from app.database.models import AuditRecord
from app.services.agent_auth import sign_request


def test_authenticated_rejected_action_result_is_audited(client) -> None:
    enrollment = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": "result-rejection-audit-host",
            "display_name": "result-rejection-audit-agent",
            "agent_version": "test",
        },
    )
    assert enrollment.status_code == 201, enrollment.text
    agent = enrollment.json()

    path_action_id = str(uuid4())
    payload_action_id = str(uuid4())
    target = f"/api/v1/actions/{path_action_id}/result"
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "schema_version": "1.0",
        "action_id": payload_action_id,
        "agent_id": agent["agent_id"],
        "host_id": "result-rejection-audit-host",
        "status": "executing",
        "started_at": now,
        "completed_at": None,
        "result": {},
        "error": None,
        "evidence": {"executor": "test"},
        "agent_version": "test",
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = "nonce-" + uuid4().hex
    headers = {
        "Content-Type": "application/json",
        "X-QWR-Agent-ID": agent["agent_id"],
        "X-QWR-Key-ID": agent["key_id"],
        "X-QWR-Timestamp": timestamp,
        "X-QWR-Nonce": nonce,
        "X-QWR-Signature": sign_request(
            agent["secret"],
            method="POST",
            target=target,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        ),
    }

    rejected = client.post(target, content=body, headers=headers)
    assert rejected.status_code == 422
    assert rejected.json()["detail"]["code"] == "action_path_mismatch"

    with client.app.state.database.session_factory() as session:
        audits = list(
            session.scalars(
                select(AuditRecord).where(
                    AuditRecord.action == "response_action_result_rejected",
                    AuditRecord.resource_id == path_action_id,
                )
            )
        )
        assert len(audits) == 1
        assert audits[0].actor_id == agent["agent_id"]
        assert audits[0].details == {"code": "action_path_mismatch"}

    verification = client.get("/api/v1/audit/verify")
    assert verification.status_code == 200
    assert verification.json()["valid"] is True
