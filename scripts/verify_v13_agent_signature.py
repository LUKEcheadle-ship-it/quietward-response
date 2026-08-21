#!/usr/bin/env python3
from __future__ import annotations

import importlib.metadata
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
PROTOCOL = BACKEND / "app" / "v13_agent_signature.py"
TESTS = BACKEND / "tests_v13" / "test_agent_signature_protocol.py"


def _run(command: list[str], *, cwd: Path) -> None:
    print("\n>>>", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def _cryptography_version() -> str:
    try:
        version = importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError as exc:
        raise RuntimeError(
            "v1.3 signature prototype requires the vetted cryptography package"
        ) from exc
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:[A-Za-z0-9.+-]*)?", version):
        raise RuntimeError(f"unexpected cryptography package version string: {version}")
    return version


def _source_contract() -> None:
    protocol = PROTOCOL.read_text(encoding="utf-8")
    design = (ROOT / "docs" / "V13_AGENT_KEY_PROTECTION_DESIGN.md").read_text(
        encoding="utf-8"
    )
    required = (
        'PROTOCOL_VERSION: Final[str] = "qwr-agent-signature-v1"',
        "Ed25519PublicKey",
        "canonical_agent_message",
        "key_id_for_public_key",
        "public key does not match key_id",
        "body_hash = hashlib.sha256(body).hexdigest()",
        "agent_id",
        "key_id",
        "nonce",
        "timestamp",
        "target",
    )
    missing = [fragment for fragment in required if fragment not in protocol]
    if missing:
        raise RuntimeError(f"v1.3 public-key protocol surface incomplete: {missing}")

    # The server-side verifier must contain no private-key generation or private
    # serialization path. Private key ownership belongs exclusively to endpoints.
    for forbidden in (
        "Ed25519PrivateKey",
        "private_bytes",
        "generate_private_key",
        "BestAvailableEncryption",
    ):
        if forbidden in protocol:
            raise RuntimeError(f"server verifier contains endpoint-private operation: {forbidden}")

    if "database-only compromise must not be sufficient" not in design.lower():
        raise RuntimeError("v1.3 key-protection design objective is missing")
    if "do not implement custom cryptography" not in design.lower():
        raise RuntimeError("v1.3 custom-crypto prohibition is missing")


def main() -> int:
    version = _cryptography_version()
    _source_contract()
    _run([sys.executable, "-m", "compileall", "-q", str(PROTOCOL)], cwd=ROOT)
    _run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            str(TESTS),
        ],
        cwd=ROOT,
    )
    print("\nV1.3 AGENT PUBLIC-KEY SIGNATURE PROTOTYPE: PASS")
    print(f"cryptography_version={version}")
    print("protocol=qwr-agent-signature-v1")
    print("algorithm=Ed25519")
    print("server_private_key_material=absent")
    print("canonical_field_substitution_tests=PASS")
    print("production_integration=NOT_YET_ENABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
