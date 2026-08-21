#!/usr/bin/env python3
from __future__ import annotations

import importlib.metadata
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
MODULE = BACKEND / "app" / "v13_agent_rotation.py"
TESTS = BACKEND / "tests_v13" / "test_agent_rotation_protocol.py"


def _run(command: list[str]) -> None:
    print("\n>>>", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> int:
    try:
        version = importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError as exc:
        raise RuntimeError("v1.3 rotation prototype requires cryptography") from exc

    source = MODULE.read_text(encoding="utf-8")
    for fragment in (
        'ROTATION_PROTOCOL: Final[str] = "qwr-agent-key-rotation-v1"',
        "canonical_rotation_prepare",
        "canonical_rotation_activate",
        "verify_rotation_prepare",
        "verify_rotation_activation",
        "replacement key must differ from current key",
        "rotation proposal has expired",
    ):
        if fragment not in source:
            raise RuntimeError(f"v1.3 rotation protocol surface missing: {fragment}")
    for forbidden in (
        "Ed25519PrivateKey",
        "private_bytes",
        "generate_private_key",
    ):
        if forbidden in source:
            raise RuntimeError(f"server rotation verifier contains private-key operation: {forbidden}")

    _run([sys.executable, "-m", "compileall", "-q", str(MODULE)])
    _run([sys.executable, "-m", "pytest", "-q", str(TESTS)])
    print("\nV1.3 DUAL-PROOF AGENT ROTATION PROTOTYPE: PASS")
    print(f"cryptography_version={version}")
    print("current_key_authorization=required")
    print("replacement_key_possession=required")
    print("server_private_key_material=absent")
    print("production_integration=NOT_YET_ENABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
