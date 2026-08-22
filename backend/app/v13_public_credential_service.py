from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.v13_agent_signature import AgentSignatureError, PublicAgentCredential
from app.v13_public_credential_model import AgentPublicCredentialRecord


ACTIVE = "active"
PENDING = "pending"
REVOKED = "revoked"
EXPIRED = "expired"
_ALLOWED_STATUSES = {ACTIVE, PENDING, REVOKED, EXPIRED}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _rows_for_agent(session: Session, agent_id: str) -> list[AgentPublicCredentialRecord]:
    return list(
        session.scalars(
            select(AgentPublicCredentialRecord)
            .where(AgentPublicCredentialRecord.agent_id == agent_id)
            .order_by(AgentPublicCredentialRecord.created_at.asc())
        )
    )


def _expire_pending_rows(
    session: Session,
    agent_id: str,
    *,
    now: datetime,
) -> None:
    for row in _rows_for_agent(session, agent_id):
        if (
            row.status == PENDING
            and row.expires_at is not None
            and _as_utc(row.expires_at) <= now
        ):
            row.status = EXPIRED
    session.flush()


def active_public_credential(
    session: Session,
    agent_id: str,
) -> AgentPublicCredentialRecord | None:
    rows = list(
        session.scalars(
            select(AgentPublicCredentialRecord).where(
                AgentPublicCredentialRecord.agent_id == agent_id,
                AgentPublicCredentialRecord.status == ACTIVE,
            )
        )
    )
    if len(rows) > 1:
        raise AgentSignatureError("multiple active public credentials exist for agent")
    return rows[0] if rows else None


def pending_public_credential(
    session: Session,
    agent_id: str,
    *,
    now: datetime | None = None,
) -> AgentPublicCredentialRecord | None:
    now = now or _utcnow()
    _expire_pending_rows(session, agent_id, now=now)
    rows = list(
        session.scalars(
            select(AgentPublicCredentialRecord).where(
                AgentPublicCredentialRecord.agent_id == agent_id,
                AgentPublicCredentialRecord.status == PENDING,
            )
        )
    )
    if len(rows) > 1:
        raise AgentSignatureError("multiple pending public credentials exist for agent")
    return rows[0] if rows else None


def create_initial_public_credential(
    session: Session,
    credential: PublicAgentCredential,
    *,
    now: datetime | None = None,
) -> AgentPublicCredentialRecord:
    now = now or _utcnow()
    if active_public_credential(session, credential.agent_id) is not None:
        raise AgentSignatureError("agent already has an active public credential")
    if pending_public_credential(session, credential.agent_id, now=now) is not None:
        raise AgentSignatureError("agent has a pending public credential")
    row = AgentPublicCredentialRecord(
        agent_id=credential.agent_id,
        key_id=credential.key_id,
        algorithm=credential.algorithm,
        protocol_version=credential.protocol_version,
        public_key_b64=credential.public_key_b64,
        status=ACTIVE,
        created_at=now,
        activated_at=now,
        revoked_at=None,
        expires_at=None,
    )
    session.add(row)
    session.flush()
    return row


def stage_public_credential_replacement(
    session: Session,
    credential: PublicAgentCredential,
    *,
    expires_at: datetime,
    now: datetime | None = None,
) -> AgentPublicCredentialRecord:
    now = now or _utcnow()
    expires_at = _as_utc(expires_at)
    if expires_at <= now:
        raise AgentSignatureError("replacement public credential expiry must be in the future")
    active = active_public_credential(session, credential.agent_id)
    if active is None:
        raise AgentSignatureError("agent has no active public credential")
    if active.key_id == credential.key_id:
        raise AgentSignatureError("replacement key must differ from current key")
    if pending_public_credential(session, credential.agent_id, now=now) is not None:
        raise AgentSignatureError("agent already has a pending public credential")
    row = AgentPublicCredentialRecord(
        agent_id=credential.agent_id,
        key_id=credential.key_id,
        algorithm=credential.algorithm,
        protocol_version=credential.protocol_version,
        public_key_b64=credential.public_key_b64,
        status=PENDING,
        created_at=now,
        activated_at=None,
        revoked_at=None,
        expires_at=expires_at,
    )
    session.add(row)
    session.flush()
    return row


def activate_public_credential_replacement(
    session: Session,
    agent_id: str,
    replacement_key_id: str,
    *,
    now: datetime | None = None,
) -> tuple[AgentPublicCredentialRecord, AgentPublicCredentialRecord]:
    now = now or _utcnow()
    current = active_public_credential(session, agent_id)
    if current is None:
        raise AgentSignatureError("agent has no active public credential")
    pending = pending_public_credential(session, agent_id, now=now)
    if pending is None or pending.key_id != replacement_key_id:
        raise AgentSignatureError("replacement public credential is not the current pending key")
    if pending.expires_at is None or _as_utc(pending.expires_at) <= now:
        pending.status = EXPIRED
        session.flush()
        raise AgentSignatureError("replacement public credential has expired")

    current.status = REVOKED
    current.revoked_at = now
    pending.status = ACTIVE
    pending.activated_at = now
    pending.expires_at = None
    session.flush()
    return current, pending


def revoke_active_public_credential(
    session: Session,
    agent_id: str,
    *,
    now: datetime | None = None,
) -> AgentPublicCredentialRecord:
    now = now or _utcnow()
    active = active_public_credential(session, agent_id)
    if active is None:
        raise AgentSignatureError("agent has no active public credential")
    active.status = REVOKED
    active.revoked_at = now
    pending = pending_public_credential(session, agent_id, now=now)
    if pending is not None:
        pending.status = REVOKED
        pending.revoked_at = now
    session.flush()
    return active


def public_credential_can_verify(
    row: AgentPublicCredentialRecord,
    *,
    now: datetime | None = None,
) -> bool:
    now = now or _utcnow()
    if row.status != ACTIVE:
        return False
    if row.revoked_at is not None:
        return False
    if row.expires_at is not None and _as_utc(row.expires_at) <= now:
        return False
    if row.algorithm != "Ed25519" or row.protocol_version != "qwr-agent-signature-v1":
        return False
    return True


def validate_public_credential_rows(rows: list[AgentPublicCredentialRecord]) -> None:
    active = [row for row in rows if row.status == ACTIVE]
    pending = [row for row in rows if row.status == PENDING]
    if len(active) > 1:
        raise AgentSignatureError("multiple active public credentials exist")
    if len(pending) > 1:
        raise AgentSignatureError("multiple pending public credentials exist")
    for row in rows:
        if row.status not in _ALLOWED_STATUSES:
            raise AgentSignatureError("unknown public credential status")
        if row.status == REVOKED and row.revoked_at is None:
            raise AgentSignatureError("revoked public credential is missing revocation time")
        if row.status == ACTIVE and row.activated_at is None:
            raise AgentSignatureError("active public credential is missing activation time")
