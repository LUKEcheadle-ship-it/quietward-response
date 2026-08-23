from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
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
DEFAULT_PENDING_KEY_SECONDS = 300
EVENT_INGESTION_SUBKEY_DOMAIN = b"quietward-response-event-ingestion-v1\0"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def derive_hmac_key(secret: str) -> bytes:
    """Derive fixed-size HMAC key material from the one-time enrollment secret."""
    return hashlib.sha256(("quietward-response-v1:" + secret).encode("utf-8")).digest()


def derive_event_ingestion_subkey(agent_hmac_key: bytes) -> bytes:
    """Derive a least-privilege key accepted only by the QuietWard event route."""
    if len(agent_hmac_key) != 32:
        raise ValueError("agent HMAC key must be 32 bytes")
    return hmac.new(
        agent_hmac_key,
        EVENT_INGESTION_SUBKEY_DOMAIN,
        hashlib.sha256,
    ).digest()


def derive_event_ingestion_subkey_from_secret(secret: str) -> bytes:
    return derive_event_ingestion_subkey(derive_hmac_key(secret))


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


def sign_event_ingestion_request(
    event_subkey: bytes,
    *,
    method: str,
    target: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> str:
    if len(event_subkey) != 32:
        raise ValueError("event-ingestion subkey must be 32 bytes")
    return hmac.new(
        event_subkey,
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


def prepare_agent_key_rotation(
    session: Session,
    agent: AgentRecord,
    *,
    pending_seconds: int = DEFAULT_PENDING_KEY_SECONDS,
) -> tuple[str, str, datetime]:
    if not 60 <= pending_seconds <= 900:
        raise ValueError("pending agent key lifetime must be between 60 and 900 seconds")
    secret = secrets.token_urlsafe(32)
    pending_key_id = str(uuid4())
    agent.pending_key_id = pending_key_id
    agent.pending_hmac_key_b64 = base64.b64encode(derive_hmac_key(secret)).decode("ascii")
    agent.pending_key_expires_at = _utcnow() + timedelta(seconds=pending_seconds)
    session.flush()
    return secret, pending_key_id, agent.pending_key_expires_at


def activate_pending_agent_key(
    session: Session,
    agent: AgentRecord,
) -> datetime:
    now = _utcnow()
    if (
        not agent.pending_key_id
        or not agent.pending_hmac_key_b64
        or agent.pending_key_expires_at is None
        or _as_utc(agent.pending_key_expires_at) <= now
    ):
        raise ValueError("pending agent credential is missing or expired")

    old_key_id = agent.key_id
    agent.key_id = agent.pending_key_id
    agent.hmac_key_b64 = agent.pending_hmac_key_b64
    agent.pending_key_id = None
    agent.pending_hmac_key_b64 = None
    agent.pending_key_expires_at = None
    agent.previous_key_id = old_key_id
    agent.previous_key_revoked_at = now
    session.flush()
    return now


def _auth_error(code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": code, "message": message},
    )


def _normal_verification_key(agent: AgentRecord, key_id: str, _now: datetime) -> bytes:
    if hmac.compare_digest(agent.key_id, key_id):
        return base64.b64decode(agent.hmac_key_b64)
    raise _auth_error("invalid_key_id", "credential key identifier does not match")


def _event_ingestion_verification_keys(
    agent: AgentRecord,
    key_id: str,
    _now: datetime,
) -> tuple[bytes, bytes]:
    if not hmac.compare_digest(agent.key_id, key_id):
        raise _auth_error("invalid_key_id", "credential key identifier does not match")
    try:
        main_key = base64.b64decode(agent.hmac_key_b64)
        return derive_event_ingestion_subkey(main_key), main_key
    except (ValueError, TypeError) as exc:
        raise _auth_error("invalid_agent_key", "stored endpoint key is invalid") from exc


def _pending_verification_key(agent: AgentRecord, key_id: str, now: datetime) -> bytes:
    if (
        agent.pending_key_id
        and agent.pending_hmac_key_b64
        and agent.pending_key_expires_at is not None
        and _as_utc(agent.pending_key_expires_at) > now
        and hmac.compare_digest(agent.pending_key_id, key_id)
    ):
        return base64.b64decode(agent.pending_hmac_key_b64)
    raise _auth_error("invalid_pending_key", "pending credential is missing, expired, or does not match")


VerificationKeys = bytes | tuple[bytes, ...]


def _verify_agent_request_with_key_selector(
    session: Session,
    request: Request,
    body: bytes,
    *,
    replay_window_seconds: int,
    allow_disabled: bool,
    selector: Callable[[AgentRecord, str, datetime], VerificationKeys],
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

    try:
        request_epoch = int(timestamp_text)
    except (TypeError, ValueError) as exc:
        raise _auth_error("invalid_timestamp", "timestamp must be Unix epoch seconds") from exc

    now_epoch = int(time.time())
    now = _utcnow()
    if abs(now_epoch - request_epoch) > replay_window_seconds:
        raise _auth_error("stale_request", "signed request is outside the replay window")
    if len(nonce) < 16 or len(nonce) > 128:
        raise _auth_error("invalid_nonce", "nonce length is invalid")

    selected = selector(agent, key_id, now)
    verification_keys = selected if isinstance(selected, tuple) else (selected,)
    target = canonical_target(request.url.path, request.url.query)
    canonical = canonical_request(
        method=request.method,
        target=target,
        timestamp=timestamp_text,
        nonce=nonce,
        body=body,
    )
    valid_signature = False
    for verification_key in verification_keys:
        expected = hmac.new(verification_key, canonical, hashlib.sha256).hexdigest()
        valid_signature = hmac.compare_digest(expected, signature) or valid_signature
    if not valid_signature:
        raise _auth_error("invalid_signature", "request signature is invalid")

    cutoff = now - timedelta(seconds=replay_window_seconds * 2)
    session.execute(delete(AgentNonceRecord).where(AgentNonceRecord.timestamp < cutoff))
    session.add(AgentNonceRecord(agent_id=agent.agent_id, nonce=nonce, timestamp=now))
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise _auth_error("replayed_nonce", "nonce has already been used") from exc

    agent.last_seen = now
    session.flush()
    session.commit()
    return agent


def verify_agent_request(
    session: Session,
    request: Request,
    body: bytes,
    *,
    replay_window_seconds: int,
    allow_disabled: bool = False,
) -> AgentRecord:
    return _verify_agent_request_with_key_selector(
        session,
        request,
        body,
        replay_window_seconds=replay_window_seconds,
        allow_disabled=allow_disabled,
        selector=_normal_verification_key,
    )


def verify_agent_event_request(
    session: Session,
    request: Request,
    body: bytes,
    *,
    replay_window_seconds: int,
) -> AgentRecord:
    """Accept the least-privilege event subkey or the full endpoint key for compatibility."""
    return _verify_agent_request_with_key_selector(
        session,
        request,
        body,
        replay_window_seconds=replay_window_seconds,
        allow_disabled=False,
        selector=_event_ingestion_verification_keys,
    )


def verify_pending_agent_request(
    session: Session,
    request: Request,
    body: bytes,
    *,
    replay_window_seconds: int,
) -> AgentRecord:
    return _verify_agent_request_with_key_selector(
        session,
        request,
        body,
        replay_window_seconds=replay_window_seconds,
        allow_disabled=False,
        selector=_pending_verification_key,
    )
