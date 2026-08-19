from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import HTTPException, Request, status
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.models import AgentNonceRecord, AgentRecord

HEADER_AGENT_ID = "X-QWR-Agent-ID"
HEADER_TIMESTAMP = "X-QWR-Timestamp"
HEADER_NONCE = "X-QWR-Nonce"
HEADER_SIGNATURE = "X-QWR-Signature"
HEADER_KEY_ID = "X-QWR-Key-ID"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def derive_hmac_key(secret: str) -> bytes:
    """Derive fixed-size HMAC key material from the one-time enrollment secret."""
    return hashlib.sha256(("quietward-response-v1:" + secret).encode("utf-8")).digest()


def canonical_target(path: str, query: str = "") -> str:
    return path if not query else f"{path}?{query}"


def canonical_request(
    *, method: str, target: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join(
        [method.upper(), target, timestamp, nonce, body_hash]
    ).encode("utf-8")


def sign_request(
    secret: str,
    *,
    method: str,
    target: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> str:
    key = derive_hmac_key(secret)
    return hmac.new(
        key,
        canonical_request(
            method=method,
            target=target,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        ),
        hashlib.sha256,
    ).hexdigest()


def enroll_agent(
    session: Session,
    *,
    host_id: str,
    display_name: str,
    agent_version: str | None,
) -> tuple[AgentRecord, str]:
    secret = secrets.token_urlsafe(32)
    agent = AgentRecord(
        agent_id=str(uuid4()),
        host_id=host_id,
        display_name=display_name,
        key_id=str(uuid4()),
        hmac_key_b64=base64.b64encode(derive_hmac_key(secret)).decode("ascii"),
        agent_version=agent_version,
        enabled=True,
    )
    session.add(agent)
    session.flush()
    return agent, secret


def _auth_error(code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": code, "message": message},
    )


def verify_agent_request(
    session: Session,
    request: Request,
    body: bytes,
    *,
    replay_window_seconds: int,
    allow_disabled: bool = False,
) -> AgentRecord:
    agent_id = request.headers.get(HEADER_AGENT_ID)
    timestamp_text = request.headers.get(HEADER_TIMESTAMP)
    nonce = request.headers.get(HEADER_NONCE)
    signature = request.headers.get(HEADER_SIGNATURE)
    key_id = request.headers.get(HEADER_KEY_ID)
    if not all((agent_id, timestamp_text, nonce, signature, key_id)):
        raise _auth_error("missing_agent_auth", "agent authentication headers are required")

    agent = session.get(AgentRecord, agent_id)
    if agent is None:
        raise _auth_error("unknown_or_disabled_agent", "agent is unknown or disabled")
    if not agent.enabled and not allow_disabled:
        raise _auth_error("unknown_or_disabled_agent", "agent is unknown or disabled")
    if not hmac.compare_digest(agent.key_id, key_id):
        raise _auth_error("invalid_key_id", "credential key identifier does not match")

    try:
        request_epoch = int(timestamp_text)
    except (TypeError, ValueError) as exc:
        raise _auth_error("invalid_timestamp", "timestamp must be Unix epoch seconds") from exc

    now_epoch = int(time.time())
    if abs(now_epoch - request_epoch) > replay_window_seconds:
        raise _auth_error("stale_request", "signed request is outside the replay window")

    if len(nonce) < 16 or len(nonce) > 128:
        raise _auth_error("invalid_nonce", "nonce length is invalid")

    target = canonical_target(request.url.path, request.url.query)
    expected = hmac.new(
        base64.b64decode(agent.hmac_key_b64),
        canonical_request(
            method=request.method,
            target=target,
            timestamp=timestamp_text,
            nonce=nonce,
            body=body,
        ),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise _auth_error("invalid_signature", "request signature is invalid")

    cutoff = _utcnow() - timedelta(seconds=replay_window_seconds * 2)
    session.execute(delete(AgentNonceRecord).where(AgentNonceRecord.timestamp < cutoff))
    session.add(AgentNonceRecord(agent_id=agent.agent_id, nonce=nonce, timestamp=_utcnow()))
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise _auth_error("replayed_nonce", "nonce has already been used") from exc

    agent.last_seen = _utcnow()
    session.flush()

    # Authentication state is committed before the business operation runs. This
    # makes a valid nonce single-use even when a later host/action/schema check
    # rejects the request and its transaction is rolled back.
    session.commit()
    return agent
