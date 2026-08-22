from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from app.v13_agent_signature import verify_ed25519_signature
from scripts.v13_endpoint_identity import (
    EndpointIdentity,
    EndpointIdentityError,
    load_development_identity_file,
    write_development_identity_file,
)


def test_endpoint_identity_generates_private_key_locally_and_server_verifies_publicly() -> None:
    identity = EndpointIdentity.generate(agent_id="agent-v13-endpoint")
    body = b'{"status":"succeeded"}'
    signature = identity.sign_request(
        method="POST",
        target="/api/v1/actions/00000000-0000-0000-0000-000000000001/result",
        timestamp="1787353200",
        nonce="0123456789abcdef0123456789abcdef",
        body=body,
    )
    verify_ed25519_signature(
        public_key_b64=identity.public_key_b64,
        signature_b64=signature,
        method="POST",
        target="/api/v1/actions/00000000-0000-0000-0000-000000000001/result",
        timestamp="1787353200",
        nonce="0123456789abcdef0123456789abcdef",
        body=body,
        agent_id=identity.agent_id,
        key_id=identity.key_id,
    )


def test_endpoint_identity_does_not_expose_private_key_as_public_attribute() -> None:
    identity = EndpointIdentity.generate(agent_id="agent-v13-endpoint")
    assert identity.public_key_b64
    assert identity.key_id.startswith("qwrpk1_")
    public_attributes = {
        name for name in dir(identity) if not name.startswith("_")
    }
    assert "private_key" not in public_attributes
    assert "private_key_b64" not in public_attributes


def test_development_file_store_requires_explicit_opt_in(tmp_path: Path) -> None:
    identity = EndpointIdentity.generate(agent_id="agent-v13-file")
    path = (tmp_path / "identity.json").resolve()
    with pytest.raises(EndpointIdentityError, match="requires explicit opt-in"):
        write_development_identity_file(path, identity)


def test_development_file_store_round_trips_only_with_explicit_opt_in(tmp_path: Path) -> None:
    identity = EndpointIdentity.generate(agent_id="agent-v13-file")
    path = (tmp_path / "identity.json").resolve()
    write_development_identity_file(
        path,
        identity,
        explicitly_allow_development_file_store=True,
    )
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    loaded = load_development_identity_file(
        path,
        explicitly_allow_development_file_store=True,
    )
    assert loaded.agent_id == identity.agent_id
    assert loaded.key_id == identity.key_id
    assert loaded.public_key_b64 == identity.public_key_b64

    message = b"restart-persistence-test"
    assert loaded.sign(message) == identity.sign(message)


def test_development_file_store_rejects_symlink_and_weak_posix_permissions(tmp_path: Path) -> None:
    identity = EndpointIdentity.generate(agent_id="agent-v13-file")
    path = (tmp_path / "identity.json").resolve()
    write_development_identity_file(
        path,
        identity,
        explicitly_allow_development_file_store=True,
    )

    if os.name != "nt":
        path.chmod(0o644)
        with pytest.raises(EndpointIdentityError, match="0600 or stricter"):
            load_development_identity_file(
                path,
                explicitly_allow_development_file_store=True,
            )
        path.chmod(0o600)
        link = (tmp_path / "identity-link.json").resolve()
        link.symlink_to(path)
        with pytest.raises(EndpointIdentityError, match="must not be a symlink"):
            load_development_identity_file(
                link,
                explicitly_allow_development_file_store=True,
            )


def test_development_store_is_explicitly_not_production_key_storage() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "scripts" / "v13_endpoint_identity.py").read_text(encoding="utf-8")
    lower = source.lower()
    assert "development-only private key persistence" in lower
    assert "prohibited for a production v1.3 release" in lower
    assert "os-backed/private endpoint" in lower
    assert "explicitly_allow_development_file_store" in source
