from __future__ import annotations

from pathlib import Path

from scripts.audit_v12_sensitive_artifacts import _reason


def test_sensitive_artifact_audit_blocks_agent_credentials_rotation_and_local_privacy_keys() -> None:
    blocked = {
        "agent.json": "agent credential/config filename",
        "response-agent.json": "agent credential/config filename",
        "quietward-response-agent.json": "agent credential/config filename",
        "agent.json.next": "staged agent rotation credential (.next)",
        "response-agent.json.next": "staged agent rotation credential (.next)",
        "response-agent-network-privacy.bin": "endpoint-local network pseudonym key",
        ".env": "environment secret file",
        ".env.production": "environment secret file",
        "client.key": "private key/certificate container",
        "client.p12": "private key/certificate container",
    }
    for name, reason in blocked.items():
        assert _reason(Path(name)) == reason


def test_sensitive_artifact_audit_allows_documentation_and_public_examples() -> None:
    allowed = (
        ".env.example",
        "docs/agent-security.md",
        "backend/tests/test_agent.json.txt",
        "checkpoint.json",
        "README.md",
        "package-lock.json",
    )
    for name in allowed:
        assert _reason(Path(name)) is None
