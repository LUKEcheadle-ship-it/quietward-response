from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

from app.v13_agent_signature import AgentSignatureError, PublicAgentCredential


CredentialStatus = Literal["active", "pending", "revoked", "expired"]


@dataclass(frozen=True, slots=True)
class PublicCredentialState:
    credential: PublicAgentCredential
    status: CredentialStatus
    created_at_epoch: int
    activated_at_epoch: int | None = None
    revoked_at_epoch: int | None = None
    expires_at_epoch: int | None = None

    def __post_init__(self) -> None:
        if self.created_at_epoch <= 0:
            raise AgentSignatureError("credential creation time is invalid")
        if self.status == "active" and self.activated_at_epoch is None:
            raise AgentSignatureError("active credential requires activation time")
        if self.status == "pending":
            if self.expires_at_epoch is None or self.expires_at_epoch <= self.created_at_epoch:
                raise AgentSignatureError("pending credential requires a later expiry")
            if self.activated_at_epoch is not None or self.revoked_at_epoch is not None:
                raise AgentSignatureError("pending credential cannot already be activated/revoked")
        if self.status == "revoked" and self.revoked_at_epoch is None:
            raise AgentSignatureError("revoked credential requires revocation time")
        if self.status == "expired" and self.expires_at_epoch is None:
            raise AgentSignatureError("expired credential requires expiry time")

    @property
    def key_id(self) -> str:
        return self.credential.key_id


def new_active_credential(
    credential: PublicAgentCredential,
    *,
    now_epoch: int,
) -> PublicCredentialState:
    return PublicCredentialState(
        credential=credential,
        status="active",
        created_at_epoch=now_epoch,
        activated_at_epoch=now_epoch,
    )


def new_pending_credential(
    credential: PublicAgentCredential,
    *,
    now_epoch: int,
    expires_at_epoch: int,
) -> PublicCredentialState:
    return PublicCredentialState(
        credential=credential,
        status="pending",
        created_at_epoch=now_epoch,
        expires_at_epoch=expires_at_epoch,
    )


def expire_pending(
    pending: PublicCredentialState,
    *,
    now_epoch: int,
) -> PublicCredentialState:
    if pending.status != "pending":
        raise AgentSignatureError("only pending credential can expire")
    if pending.expires_at_epoch is None or now_epoch <= pending.expires_at_epoch:
        raise AgentSignatureError("pending credential has not expired")
    return replace(pending, status="expired")


def activate_replacement(
    current: PublicCredentialState,
    pending: PublicCredentialState,
    *,
    now_epoch: int,
) -> tuple[PublicCredentialState, PublicCredentialState]:
    if current.status != "active":
        raise AgentSignatureError("current credential is not active")
    if pending.status != "pending":
        raise AgentSignatureError("replacement credential is not pending")
    if current.credential.agent_id != pending.credential.agent_id:
        raise AgentSignatureError("replacement belongs to another agent")
    if current.key_id == pending.key_id:
        raise AgentSignatureError("replacement key must differ from current key")
    if pending.expires_at_epoch is None or now_epoch > pending.expires_at_epoch:
        raise AgentSignatureError("replacement credential has expired")

    revoked = replace(
        current,
        status="revoked",
        revoked_at_epoch=now_epoch,
    )
    activated = replace(
        pending,
        status="active",
        activated_at_epoch=now_epoch,
        expires_at_epoch=None,
    )
    return revoked, activated


def credential_can_verify(
    state: PublicCredentialState,
    *,
    now_epoch: int,
) -> bool:
    if state.status != "active":
        return False
    if state.revoked_at_epoch is not None:
        return False
    if state.expires_at_epoch is not None and now_epoch > state.expires_at_epoch:
        return False
    return True
