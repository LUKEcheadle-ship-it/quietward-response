from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.config import Settings
from app.database.models import AuditRecord, IncidentRecord
from app.main import create_app


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


TOKENS = {
    "viewer": "viewer-secret-token-v12",
    "responder": "responder-secret-token-v12",
    "admin": "admin-secret-token-v12",
}
CREDENTIALS = [
    f"view-user|viewer|{_hash(TOKENS['viewer'])}",
    f"response-user|responder|{_hash(TOKENS['responder'])}",
    f"admin-user|admin|{_hash(TOKENS['admin'])}",
]
AUDIT_SECRET = "production-audit-checkpoint-secret-v12-test-only"


def _headers(role: str, **extra: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKENS[role]}", **extra}


def _production_client(tmp_path: Path) -> TestClient:
    database = tmp_path / "rbac.db"
    settings = Settings(
        environment="production",
        database_url=f"sqlite:///{database.as_posix()}",
        api_host="0.0.0.0",
        cors_origins=["https://response.example.test"],
        log_level="WARNING",
        enrollment_token="production-enrollment-token-v12-change-me",
        analyst_credentials=CREDENTIALS,
        require_agent_auth_for_quietward_events=True,
        audit_checkpoint_secret=AUDIT_SECRET,
    )
    return TestClient(create_app(settings=settings))


def test_remote_runtime_requires_hashed_analyst_credentials(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="QWR_ANALYST_CREDENTIALS is required"):
        Settings(
            environment="production",
            database_url=f"sqlite:///{(tmp_path / 'missing.db').as_posix()}",
            api_host="0.0.0.0",
            enrollment_token="production-enrollment-token-v12-change-me",
            analyst_credentials=[],
            audit_checkpoint_secret=AUDIT_SECRET,
        )


def test_remote_runtime_requires_independent_audit_checkpoint_secret(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="QWR_AUDIT_CHECKPOINT_SECRET must be replaced"):
        Settings(
            environment="production",
            database_url=f"sqlite:///{(tmp_path / 'audit-secret.db').as_posix()}",
            api_host="0.0.0.0",
            enrollment_token="production-enrollment-token-v12-change-me",
            analyst_credentials=CREDENTIALS,
        )


def test_invalid_or_duplicate_credential_hashes_fail_startup(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        Settings(
            environment="production",
            database_url=f"sqlite:///{(tmp_path / 'bad.db').as_posix()}",
            api_host="0.0.0.0",
            enrollment_token="production-enrollment-token-v12-change-me",
            analyst_credentials=["alice|admin|not-a-hash"],
            audit_checkpoint_secret=AUDIT_SECRET,
        )

    duplicate = _hash("same-token")
    with pytest.raises(ValueError, match="token hashes must be unique"):
        Settings(
            environment="production",
            database_url=f"sqlite:///{(tmp_path / 'dupe.db').as_posix()}",
            api_host="0.0.0.0",
            enrollment_token="production-enrollment-token-v12-change-me",
            analyst_credentials=[
                f"alice|admin|{duplicate}",
                f"bob|viewer|{duplicate}",
            ],
            audit_checkpoint_secret=AUDIT_SECRET,
        )


def test_viewer_can_read_but_cannot_mutate_agent(tmp_path: Path) -> None:
    with _production_client(tmp_path) as client:
        assert client.get("/api/v1/agents").status_code == 401

        viewed = client.get("/api/v1/agents", headers=_headers("viewer"))
        assert viewed.status_code == 200
        assert viewed.headers["x-qwr-analyst-role"] == "viewer"

        enrollment = client.post(
            "/api/v1/agents/enroll",
            headers={"X-QWR-Enrollment-Token": "production-enrollment-token-v12-change-me"},
            json={
                "host_id": "host-rbac",
                "display_name": "RBAC test agent",
                "agent_version": "test",
            },
        )
        assert enrollment.status_code == 201, enrollment.text
        agent_id = enrollment.json()["agent_id"]

        viewer_patch = client.patch(
            f"/api/v1/agents/{agent_id}",
            headers=_headers("viewer"),
            json={"enabled": False},
        )
        assert viewer_patch.status_code == 403
        assert viewer_patch.json()["detail"]["required_role"] == "admin"

        responder_patch = client.patch(
            f"/api/v1/agents/{agent_id}",
            headers=_headers("responder"),
            json={"enabled": False},
        )
        assert responder_patch.status_code == 403

        admin_patch = client.patch(
            f"/api/v1/agents/{agent_id}",
            headers=_headers("admin", **{"X-Actor-ID": "spoofed-actor"}),
            json={"enabled": False},
        )
        assert admin_patch.status_code == 200, admin_patch.text
        assert admin_patch.json()["enabled"] is False

        with client.app.state.database.session_factory() as session:
            audit = session.scalars(
                select(AuditRecord)
                .where(AuditRecord.action == "agent_disabled")
                .order_by(AuditRecord.timestamp.desc())
                .limit(1)
            ).first()
            assert audit is not None
            assert audit.actor_id == "admin-user"
            assert audit.actor_id != "spoofed-actor"


def test_responder_can_change_incident_but_viewer_cannot(tmp_path: Path) -> None:
    with _production_client(tmp_path) as client:
        now = datetime.now(timezone.utc)
        with client.app.state.database.session_factory() as session:
            incident = IncidentRecord(
                incident_id="00000000-0000-0000-0000-00000000ab12",
                title="RBAC incident",
                status="new",
                severity="medium",
                confidence=0.8,
                affected_hosts=["host-rbac"],
                created_at=now,
                updated_at=now,
                first_event_at=now,
                last_event_at=now,
                event_count=0,
                probable_cause="test",
                correlation_reasons=[],
                recommended_actions=[],
            )
            session.add(incident)
            session.commit()

        viewer = client.patch(
            f"/api/v1/incidents/{incident.incident_id}",
            headers=_headers("viewer"),
            json={"status": "investigating"},
        )
        assert viewer.status_code == 403
        assert viewer.json()["detail"]["required_role"] == "responder"

        responder = client.patch(
            f"/api/v1/incidents/{incident.incident_id}",
            headers=_headers("responder", **{"X-Actor-ID": "spoofed-responder"}),
            json={"status": "investigating"},
        )
        assert responder.status_code == 200, responder.text
        assert responder.json()["status"] == "investigating"

        with client.app.state.database.session_factory() as session:
            audit = session.scalars(
                select(AuditRecord)
                .where(AuditRecord.resource_id == incident.incident_id)
                .order_by(AuditRecord.timestamp.desc())
                .limit(1)
            ).first()
            assert audit is not None
            assert audit.actor_id == "response-user"
            assert audit.actor_id != "spoofed-responder"


def test_viewer_can_export_and_verify_signed_audit_checkpoint(tmp_path: Path) -> None:
    with _production_client(tmp_path) as client:
        checkpoint = client.get(
            "/api/v1/audit/checkpoint",
            headers=_headers("viewer"),
        )
        assert checkpoint.status_code == 200, checkpoint.text
        verified = client.post(
            "/api/v1/audit/checkpoint/verify",
            headers=_headers("viewer"),
            json=checkpoint.json(),
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["valid"] is True
        assert verified.headers["x-qwr-analyst-role"] == "viewer"


def test_invalid_bearer_does_not_fall_back_to_actor_header_remotely(tmp_path: Path) -> None:
    with _production_client(tmp_path) as client:
        response = client.get(
            "/api/v1/overview",
            headers={
                "Authorization": "Bearer incorrect-token",
                "X-Actor-ID": "admin-user",
            },
        )
        assert response.status_code == 401
        assert response.json()["detail"]["code"] == "analyst_authentication_required"


def test_machine_enrollment_route_does_not_require_analyst_bearer(tmp_path: Path) -> None:
    with _production_client(tmp_path) as client:
        response = client.post(
            "/api/v1/agents/enroll",
            headers={"X-QWR-Enrollment-Token": "production-enrollment-token-v12-change-me"},
            json={
                "host_id": "host-machine-exempt",
                "display_name": "Machine auth test",
                "agent_version": "test",
            },
        )
        assert response.status_code == 201, response.text
        assert response.headers["cache-control"].startswith("no-store")
