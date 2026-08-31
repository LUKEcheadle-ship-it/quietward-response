#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import socket
import sqlite3
import tempfile
from pathlib import Path

from scripts import verify_v1


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
EXPECTED_ACTIONS = {
    "restart_quietward_demo_service",
    "collect_host_diagnostic",
    "collect_process_diagnostic",
    "collect_network_diagnostic",
}


def _migration_env(database: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["QWR_DATABASE_URL"] = f"sqlite:///{database.as_posix()}"
    env["QWR_ENVIRONMENT"] = "development"
    env["QWR_ENROLLMENT_TOKEN"] = "v11-diagnostic-verification-enrollment-token"
    return env


def _assert_v11_schema(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        required = {
            "hosts",
            "incidents",
            "events",
            "agents",
            "agent_nonces",
            "approvals",
            "actions",
            "audit_records",
            "agent_capabilities",
        }
        missing = required - tables
        if missing:
            raise RuntimeError(f"v1.1 migration missing tables: {sorted(missing)}")
        version = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        if not version or version[0] != "0003_agent_diag_caps":
            raise RuntimeError(f"unexpected v1.1 Alembic version: {version!r}")
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(agent_capabilities)")
        }
        expected_columns = {
            "agent_id",
            "agent_version",
            "supported_actions",
            "enabled_actions",
            "arbitrary_command_execution",
            "updated_at",
        }
        if not expected_columns <= columns:
            raise RuntimeError(
                f"agent capability schema missing columns: {sorted(expected_columns - columns)}"
            )


def _verify_migrations(python: str, temporary: Path) -> None:
    fresh = temporary / "fresh-v11.db"
    fresh_env = _migration_env(fresh)
    verify_v1._run([python, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, env=fresh_env)
    _assert_v11_schema(fresh)
    verify_v1._run([python, "-m", "alembic", "check"], cwd=BACKEND, env=fresh_env)

    upgraded = temporary / "upgrade-from-v1.db"
    upgraded_env = _migration_env(upgraded)
    verify_v1._run(
        [python, "-m", "alembic", "upgrade", "0002_phase2"],
        cwd=BACKEND,
        env=upgraded_env,
    )
    verify_v1._run([python, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, env=upgraded_env)
    _assert_v11_schema(upgraded)


def _verify_action_surface(python: str) -> None:
    expected = repr(EXPECTED_ACTIONS)
    code = (
        "from app.services.action_registry import ACTION_REGISTRY; "
        f"expected={expected}; actual=set(ACTION_REGISTRY); "
        "assert actual == expected, f'unexpected v1.1 actions: {sorted(actual)}'; "
        "assert not ({'terminate_process_by_handle','quarantine_artifact_by_handle',"
        "'restore_quarantined_artifact_by_handle','isolate_host','block_network'} & actual); "
        "print('v1.1 action surface:', sorted(actual))"
    )
    verify_v1._run([python, "-c", code], cwd=BACKEND)


def _verify_quick_start(python: str, temporary: Path) -> None:
    verify_v1._assert_frontend_port_available()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    database = temporary / "quick-start-v11.db"
    env = os.environ.copy()
    env.update(
        {
            "QWR_ENVIRONMENT": "development",
            "QWR_DATABASE_URL": f"sqlite:///{database.as_posix()}",
            "QWR_API_HOST": "127.0.0.1",
            "QWR_API_PORT": str(port),
            "QWR_CORS_ORIGINS": '["http://localhost:3001","http://127.0.0.1:3001"]',
            "QWR_ENROLLMENT_TOKEN": "v11-quick-start-enrollment-token",
            "QWR_SEED_DEMO": "false",
            "NEXT_PUBLIC_API_URL": f"http://localhost:{port}",
        }
    )
    verify_v1._run(
        [python, str(ROOT / "scripts" / "bootstrap_local.py"), "--smoke"],
        cwd=ROOT,
        env=env,
    )
    _assert_v11_schema(database)
    verify_v1._assert_frontend_port_available()


def _verify_quietward(quietward_repo: Path, python: str) -> None:
    if not (quietward_repo / "src" / "quietward").is_dir():
        raise RuntimeError(f"not a QuietWard checkout: {quietward_repo}")
    env = os.environ.copy()
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(quietward_repo / "src") + (os.pathsep + existing if existing else "")
    verify_v1._run([python, "-m", "compileall", "-q", "src", "tests", "scripts"], cwd=quietward_repo, env=env)
    verify_v1._run([python, "scripts/public_release_audit.py"], cwd=quietward_repo, env=env)
    verify_v1._run([python, "-m", "unittest", "discover", "-s", "tests", "-q"], cwd=quietward_repo, env=env)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the QuietWard Response v1.1 diagnostic upgrade gate."
    )
    parser.add_argument("--quietward-repo", type=Path)
    parser.add_argument("--skip-npm-audit", action="store_true")
    args = parser.parse_args()

    python = verify_v1._ensure_python()
    verify_v1._run([python, "-m", "compileall", "-q", "app", "tests"], cwd=BACKEND)
    verify_v1._run([python, "-m", "compileall", "-q", "scripts"], cwd=ROOT)
    verify_v1._run([python, str(ROOT / "scripts" / "audit_public_release.py")], cwd=ROOT)
    verify_v1._run([python, "-m", "pytest", "-W", "error"], cwd=BACKEND)
    _verify_action_surface(python)

    with tempfile.TemporaryDirectory(prefix="qwr-v11-") as temporary:
        temp_path = Path(temporary)
        _verify_migrations(python, temp_path)

        npm = shutil.which("npm")
        if npm is None:
            raise RuntimeError("npm is required for the v1.1 frontend gate")
        verify_v1._run(verify_v1._npm_command(npm, "ci"), cwd=FRONTEND)
        verify_v1._run(verify_v1._npm_command(npm, "run", "typecheck"), cwd=FRONTEND)
        verify_v1._run(verify_v1._npm_command(npm, "run", "build"), cwd=FRONTEND)
        if not args.skip_npm_audit:
            verify_v1._run(verify_v1._npm_command(npm, "audit", "--audit-level=high"), cwd=FRONTEND)
        _verify_quick_start(python, temp_path)

    if args.quietward_repo is not None:
        _verify_quietward(args.quietward_repo.resolve(), python)

    print("\nV1.1 DIAGNOSTIC UPGRADE GATE: PASS")
    if args.quietward_repo is None:
        print("Companion QuietWard suite: NOT RUN")
    if args.skip_npm_audit:
        print("npm audit: SKIPPED; this is not a final release qualification")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
