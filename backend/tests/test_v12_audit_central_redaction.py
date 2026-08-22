from __future__ import annotations

from sqlalchemy import select

from app.database.models import AuditRecord
from app.services.audit_service import (
    create_audit_checkpoint,
    record_audit,
    verify_audit_chain,
    verify_audit_checkpoint,
)
from app.services.redaction import REDACTED


CHECKPOINT_SECRET = "central-audit-redaction-checkpoint-secret-0123456789"


def test_record_audit_redacts_nested_credentials_before_hashing_and_persistence(client) -> None:
    with client.app.state.database.session_factory() as session:
        first = record_audit(
            session,
            actor_type="system",
            actor_id="redaction-test",
            action="central_redaction_test",
            resource_type="test",
            resource_id="record-1",
            details={
                "password": "hunter2",
                "nested": {
                    "access_token": "access-secret",
                    "client_secret": "client-secret",
                    "key_id": "safe-key-id",
                    "token_count": 4,
                },
                "message": "Authorization: Bearer abcdefghijklmnop password=swordfish",
            },
        )
        session.commit()

        stored = session.get(AuditRecord, first.audit_id)
        assert stored is not None
        assert stored.details["password"] == REDACTED
        assert stored.details["nested"]["access_token"] == REDACTED
        assert stored.details["nested"]["client_secret"] == REDACTED
        assert stored.details["nested"]["key_id"] == "safe-key-id"
        assert stored.details["nested"]["token_count"] == 4

        serialized = str(stored.details)
        for secret in (
            "hunter2",
            "access-secret",
            "client-secret",
            "abcdefghijklmnop",
            "swordfish",
        ):
            assert secret not in serialized

        state = verify_audit_chain(session)
        assert state["valid"] is True
        assert state["entries_checked"] >= 1


def test_central_redaction_keeps_multi_entry_chain_and_checkpoint_valid(client) -> None:
    with client.app.state.database.session_factory() as session:
        first = record_audit(
            session,
            actor_type="system",
            actor_id="redaction-test",
            action="first_redacted_entry",
            resource_type="test",
            resource_id="first",
            details={"api_key": "first-secret", "sequence": 1},
        )
        session.commit()
        checkpoint = create_audit_checkpoint(session, secret=CHECKPOINT_SECRET)

        second = record_audit(
            session,
            actor_type="analyst",
            actor_id="analyst-test",
            action="second_redacted_entry",
            resource_type="test",
            resource_id="second",
            details={
                "nested": {"refresh_token": "second-secret"},
                "sequence": 2,
            },
        )
        session.commit()

        rows = list(
            session.scalars(
                select(AuditRecord)
                .where(AuditRecord.audit_id.in_([first.audit_id, second.audit_id]))
                .order_by(AuditRecord.timestamp.asc())
            )
        )
        assert len(rows) == 2
        assert rows[0].details["api_key"] == REDACTED
        assert rows[1].details["nested"]["refresh_token"] == REDACTED
        assert "first-secret" not in str(rows[0].details)
        assert "second-secret" not in str(rows[1].details)

        chain = verify_audit_chain(session)
        assert chain["valid"] is True

        anchored = verify_audit_checkpoint(
            session,
            checkpoint=checkpoint,
            secret=CHECKPOINT_SECRET,
        )
        assert anchored["valid"] is True
        assert anchored["current_entries_checked"] >= checkpoint["entries_checked"] + 1


def test_audit_redaction_happens_before_entry_hash_is_calculated(client) -> None:
    with client.app.state.database.session_factory() as session:
        record = record_audit(
            session,
            actor_type="system",
            actor_id="redaction-test",
            action="hash_redacted_form",
            resource_type="test",
            resource_id="hash-redacted",
            details={"private_key": "private-material", "safe": "value"},
        )
        session.commit()
        original_hash = record.entry_hash
        assert original_hash
        assert record.details["private_key"] == REDACTED

        # The normal verifier recomputes from the durable redacted details. If the
        # entry hash had been calculated over pre-redaction data this would fail.
        assert verify_audit_chain(session)["valid"] is True

        session.refresh(record)
        assert record.entry_hash == original_hash
