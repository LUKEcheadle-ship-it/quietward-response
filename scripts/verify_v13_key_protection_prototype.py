#!/usr/bin/env python3
from __future__ import annotations

import importlib.metadata
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
TEST_ROOT = BACKEND / "tests_v13"
MODULES = (
    BACKEND / "app" / "v13_agent_signature.py",
    BACKEND / "app" / "v13_agent_enrollment.py",
    BACKEND / "app" / "v13_agent_rotation.py",
)


def _run(command: list[str]) -> None:
    print("\n>>>", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def _source_contract() -> None:
    sources = {path.name: path.read_text(encoding="utf-8") for path in MODULES}
    combined = "\n".join(sources.values())

    required = (
        "qwr-agent-signature-v1",
        "qwr-agent-enrollment-v1",
        "qwr-agent-key-rotation-v1",
        "Ed25519PublicKey",
        "verify_ed25519_signature",
        "verify_enrollment_key_possession",
        "verify_rotation_prepare",
        "verify_rotation_activation",
        "body_hash = hashlib.sha256(body).hexdigest()",
    )
    missing = [item for item in required if item not in combined]
    if missing:
        raise RuntimeError(f"v1.3 key-protection prototype surface missing: {missing}")

    # The server-side prototype may verify signatures only. Private-key generation,
    # serialization, storage and recovery belong to endpoint code and are not
    # allowed to creep into the server verifier modules.
    for filename, source in sources.items():
        for forbidden in (
            "Ed25519PrivateKey",
            "private_bytes",
            "generate_private_key",
            "BestAvailableEncryption",
        ):
            if forbidden in source:
                raise RuntimeError(
                    f"server verifier {filename} contains private-key operation: {forbidden}"
                )

    design = (ROOT / "docs" / "V13_AGENT_KEY_PROTECTION_DESIGN.md").read_text(
        encoding="utf-8"
    ).lower()
    for phrase in (
        "database-only compromise must not be sufficient",
        "the private key never leaves the endpoint",
        "do not solve this by adding a home-grown encryption routine",
        "no automatic fallback to plaintext",
    ):
        if phrase not in design:
            raise RuntimeError(f"v1.3 design contract missing: {phrase}")


def main() -> int:
    try:
        crypto_version = importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError as exc:
        raise RuntimeError(
            "v1.3 public-key prototype requires the vetted cryptography dependency"
        ) from exc

    _source_contract()
    _run([sys.executable, "-m", "compileall", "-q", *(str(path) for path in MODULES)])
    _run([sys.executable, "-m", "pytest", "-q", str(TEST_ROOT)])

    print("\nV1.3 AGENT KEY-PROTECTION PROTOTYPE: PASS")
    print(f"cryptography_version={crypto_version}")
    print("request_signature=Ed25519-public-key-only")
    print("enrollment_private_key_possession=required")
    print("rotation_current_key_authorization=required")
    print("rotation_replacement_key_possession=required")
    print("server_private_key_material=absent")
    print("database_migration=NOT_YET_ENABLED")
    print("production_auth_switch=NOT_YET_ENABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
