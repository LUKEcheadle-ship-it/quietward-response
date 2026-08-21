#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import socket
import sqlite3
import tempfile
from pathlib import Path

from verify_v1 import (
    BACKEND,
    FRONTEND,
    ROOT,
    _ensure_python,
    _insert_phase1_audit_row,
    _migration_env,
    _npm_command,
    _run,
)

EXPECTED_ALEMBIC_HEAD = "0003_agent_caps"


def _assert_frontend_port_available() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", 3001))
        except OSError as exc:
            raise RuntimeError(
                "frontend port 3001 is already in use; stop the existing service before v1.2 qualification"
            ) from exc


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _assert_v12_schema(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        required_tables = {
            "hosts",
            "incidents",
            "events",
            "agents",
            "agent_nonces",
            "approvals",
            "actions",
            "audit_records",
        }
        missing = required_tables - tables
        if missing:
            raise RuntimeError(f"v1.2 migration missing tables: {sorted(missing)}")

        audit_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(audit_records)")
        }
        for required in ("previous_hash", "entry_hash"):
            if required not in audit_columns:
                raise RuntimeError(f"v1.2 migration missing audit column: {required}")

        agent_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(agents)")
        }
        required_agent_columns = {
            "supported_actions",
            "enabled_actions",
            "capabilities_updated_at",
            "pending_key_id",
            "pending_hmac_key_b64",
            "pending_key_expires_at",
            "previous_key_id",
            "previous_hmac_key_b64",
            "previous_key_expires_at",
        }
        missing_agent = required_agent_columns - agent_columns
        if missing_agent:
            raise RuntimeError(
                f"v1.2 migration missing agent hardening columns: {sorted(missing_agent)}"
            )

        version = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        if not version or version[0] != EXPECTED_ALEMBIC_HEAD:
            raise RuntimeError(f"unexpected v1.2 Alembic version: {version!r}")


def _verify_v12_fresh_migration(python: str, temporary: Path) -> None:
    database = temporary / "fresh-v12.db"
    env = _migration_env(database)
    _run([python, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, env=env)
    _assert_v12_schema(database)
    _run([python, "-m", "alembic", "check"], cwd=BACKEND, env=env)


def _verify_v12_phase1_upgrade(python: str, temporary: Path) -> None:
    database = temporary / "legacy-phase1-to-v12.db"
    env = _migration_env(database)
    _run(
        [python, "-m", "alembic", "upgrade", "0001_phase1"],
        cwd=BACKEND,
        env=env,
    )
    _insert_phase1_audit_row(database)
    _run([python, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, env=env)
    _assert_v12_schema(database)

    code = (
        "from app.database.session import Database; "
        "from app.services.audit_service import backfill_legacy_audit_chain, verify_audit_chain; "
        f"db=Database('sqlite:///{database.as_posix()}'); "
        "s=db.session_factory(); "
        "count=backfill_legacy_audit_chain(s); s.commit(); "
        "result=verify_audit_chain(s); s.close(); db.dispose(); "
        "assert count == 1, count; assert result['valid'], result; "
        "print('v1.2 legacy audit backfill:', result['head_hash'])"
    )
    _run([python, "-c", code], cwd=BACKEND, env=env)


def _verify_v12_public_quick_start(python: str, temporary: Path) -> None:
    _assert_frontend_port_available()
    port = _free_port()
    database = temporary / "quick-start-v12.db"
    env = os.environ.copy()
    env.update(
        {
            "QWR_ENVIRONMENT": "development",
            "QWR_DATABASE_URL": f"sqlite:///{database.as_posix()}",
            "QWR_API_HOST": "127.0.0.1",
            "QWR_API_PORT": str(port),
            "QWR_CORS_ORIGINS": '["http://localhost:3001","http://127.0.0.1:3001"]',
            "QWR_ENROLLMENT_TOKEN": "v12-quick-start-smoke-enrollment-token",
            "QWR_SEED_DEMO": "false",
            "NEXT_PUBLIC_API_URL": f"http://localhost:{port}",
        }
    )
    _run(
        [python, str(ROOT / "scripts" / "bootstrap_local.py"), "--smoke"],
        cwd=ROOT,
        env=env,
    )
    _assert_v12_schema(database)
    _assert_frontend_port_available()


def main() -> int:
    python = _ensure_python()

    _run([python, "-m", "compileall", "-q", "app", "tests"], cwd=BACKEND)
    _run(
        [python, "-m", "compileall", "-q", "scripts", "response_agent_resources.py"],
        cwd=ROOT,
    )
    _run([python, str(ROOT / "scripts" / "audit_public_release.py")], cwd=ROOT)
    _run([python, "-m", "pytest", "-W", "error"], cwd=BACKEND)
    _run([python, str(ROOT / "scripts" / "verify_v12_surface.py")], cwd=ROOT)

    with tempfile.TemporaryDirectory(prefix="qwr-v12-alpha-") as temporary:
        temp_path = Path(temporary)
        _verify_v12_fresh_migration(python, temp_path)
        _verify_v12_phase1_upgrade(python, temp_path)

        npm = shutil.which("npm")
        if npm is None:
            raise RuntimeError("npm is required for the v1.2 alpha frontend gate")
        _run(_npm_command(npm, "ci"), cwd=FRONTEND)
        _run(_npm_command(npm, "run", "typecheck"), cwd=FRONTEND)
        _run(_npm_command(npm, "run", "build"), cwd=FRONTEND)
        _run(_npm_command(npm, "audit", "--audit-level=high"), cwd=FRONTEND)
        _verify_v12_public_quick_start(python, temp_path)

    print("\nV1.2.0-ALPHA.1 STATIC/LOCAL GATE: PASS")
    print("Backend full pytest suite: PASS")
    print("Typed action/plan surface: PASS")
    print("Opaque-handle disposable containment: PASS")
    print("Signed agent capability negotiation: PASS")
    print("Two-phase recoverable agent key rotation: PASS")
    print("Signed externalizable audit checkpoints: PASS")
    print("Analyst bearer authentication/RBAC: PASS")
    print("API request-size/rate bounds: PASS")
    print(f"Fresh and legacy migrations to {EXPECTED_ALEMBIC_HEAD}: PASS")
    print("Frontend typecheck/build/high-severity npm audit: PASS")
    print("Public quick-start and cleanup: PASS")
    print("Live standalone containment acceptance remains a separate required gate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
