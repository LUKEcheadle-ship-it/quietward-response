#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
VENV = ROOT / ".venv"


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    printable = " ".join(command)
    print(f"\n>>> ({cwd}) {printable}", flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def _venv_python() -> Path:
    candidates = [
        VENV / "Scripts" / "python.exe",
        VENV / "bin" / "python",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise RuntimeError("v1 virtual environment was not created correctly")


def _ensure_python() -> str:
    if sys.version_info < (3, 12):
        raise RuntimeError(
            f"Python 3.12+ is required to bootstrap the v1 gate; got {sys.version.split()[0]}"
        )
    if not VENV.exists():
        _run([sys.executable, "-m", "venv", str(VENV)], cwd=ROOT)
    python = str(_venv_python())
    # Always reconcile declared requirements before qualification. This makes the
    # gate usable from a fresh checkout and picks up dependency-bound fixes made
    # after a prior local venv was created.
    _run(
        [python, "-m", "pip", "install", "-q", "-r", str(BACKEND / "requirements.txt")],
        cwd=ROOT,
    )
    return python


def _assert_phase2_schema(database: Path) -> None:
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
            raise RuntimeError(f"migration missing tables: {sorted(missing)}")
        audit_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(audit_records)")
        }
        for required in ("previous_hash", "entry_hash"):
            if required not in audit_columns:
                raise RuntimeError(f"migration missing audit column: {required}")
        version = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        if not version or version[0] != "0002_phase2":
            raise RuntimeError(f"unexpected Alembic version: {version!r}")


def _migration_env(database: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["QWR_DATABASE_URL"] = f"sqlite:///{database.as_posix()}"
    env["QWR_ENVIRONMENT"] = "development"
    env["QWR_ENROLLMENT_TOKEN"] = "v1-verification-enrollment-token"
    return env


def _verify_fresh_migration(python: str, temporary: Path) -> None:
    database = temporary / "fresh.db"
    env = _migration_env(database)
    _run([python, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, env=env)
    _assert_phase2_schema(database)
    # Fail if current ORM metadata would require another migration. This protects
    # the release from model/schema drift after the frozen v1 migrations.
    _run([python, "-m", "alembic", "check"], cwd=BACKEND, env=env)


def _insert_phase1_audit_row(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO audit_records(
                audit_id, timestamp, actor_type, actor_id, action,
                resource_type, resource_id, details, incident_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                "00000000-0000-0000-0000-000000000001",
                "2026-08-18 12:00:00.000000",
                "sensor",
                "legacy-phase1",
                "event_received",
                "event",
                "legacy-event",
                "{}",
            ),
        )
        connection.commit()


def _verify_phase1_upgrade(python: str, temporary: Path) -> None:
    database = temporary / "legacy-phase1.db"
    env = _migration_env(database)

    # Build a genuine database from the frozen Phase 1 migration, add one legacy
    # unhashed audit row, then apply v1. This verifies the real upgrade path.
    _run(
        [python, "-m", "alembic", "upgrade", "0001_phase1"],
        cwd=BACKEND,
        env=env,
    )
    _insert_phase1_audit_row(database)
    _run([python, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, env=env)
    _assert_phase2_schema(database)

    # Application startup backfills a fully legacy/unhashed chain exactly once.
    code = (
        "from app.database.session import Database; "
        "from app.services.audit_service import backfill_legacy_audit_chain, verify_audit_chain; "
        f"db=Database('sqlite:///{database.as_posix()}'); "
        "s=db.session_factory(); "
        "count=backfill_legacy_audit_chain(s); s.commit(); "
        "result=verify_audit_chain(s); s.close(); db.dispose(); "
        "assert count == 1, count; assert result['valid'], result; "
        "print('legacy audit backfill:', result['head_hash'])"
    )
    _run([python, "-c", code], cwd=BACKEND, env=env)


def _verify_action_surface(python: str) -> None:
    code = (
        "from app.services.action_registry import ACTION_REGISTRY; "
        "expected={'restart_quietward_demo_service'}; "
        "actual=set(ACTION_REGISTRY); "
        "assert actual == expected, f'unexpected executable actions: {sorted(actual)}'; "
        "print('allowlisted executable actions:', sorted(actual))"
    )
    _run([python, "-c", code], cwd=BACKEND)


def _verify_quietward(quietward_repo: Path, python: str) -> None:
    if not (quietward_repo / "src" / "quietward").is_dir():
        raise RuntimeError(f"not a QuietWard checkout: {quietward_repo}")
    env = os.environ.copy()
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(quietward_repo / "src") + (os.pathsep + existing if existing else "")
    _run(
        [python, "-m", "compileall", "-q", "src", "tests", "scripts/quietward_response_demo.py"],
        cwd=quietward_repo,
        env=env,
    )
    _run(
        [python, "-m", "unittest", "discover", "-s", "tests", "-q"],
        cwd=quietward_repo,
        env=env,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the deterministic QuietWard Response v1 release gate."
    )
    parser.add_argument(
        "--quietward-repo",
        type=Path,
        help="Optional path to the companion QuietWard feature-branch checkout.",
    )
    parser.add_argument(
        "--skip-npm-audit",
        action="store_true",
        help="Skip npm audit when the machine intentionally has no network access.",
    )
    args = parser.parse_args()

    python = _ensure_python()
    print(f"QuietWard Response root: {ROOT}")
    print(f"Python: {python}")

    _run([python, "-m", "compileall", "-q", "app", "tests"], cwd=BACKEND)
    _run([python, "-m", "pytest", "-W", "error"], cwd=BACKEND)
    _verify_action_surface(python)

    with tempfile.TemporaryDirectory(prefix="qwr-v1-") as temporary:
        temp_path = Path(temporary)
        _verify_fresh_migration(python, temp_path)
        _verify_phase1_upgrade(python, temp_path)

    npm = shutil.which("npm")
    if npm is None:
        raise RuntimeError("npm is required for the v1 frontend release gate")
    # Always reproduce the frontend dependency tree from package-lock.json rather
    # than trusting whatever happens to be in an existing node_modules directory.
    _run([npm, "ci"], cwd=FRONTEND)
    _run([npm, "run", "typecheck"], cwd=FRONTEND)
    _run([npm, "run", "build"], cwd=FRONTEND)
    if not args.skip_npm_audit:
        _run([npm, "audit", "--audit-level=high"], cwd=FRONTEND)

    if args.quietward_repo is not None:
        _verify_quietward(args.quietward_repo.resolve(), python)

    print("\nV1 STATIC/LOCAL RELEASE GATE: PASS")
    if args.quietward_repo is None:
        print("Companion QuietWard suite: NOT RUN (pass --quietward-repo PATH to include it)")
    print("The live two-repository HTTP demo remains a separate acceptance check.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
