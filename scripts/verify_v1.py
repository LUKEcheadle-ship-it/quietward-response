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


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    printable = " ".join(command)
    print(f"\n>>> ({cwd}) {printable}", flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def _python() -> str:
    candidates = [
        ROOT / ".venv" / "Scripts" / "python.exe",
        ROOT / ".venv" / "bin" / "python",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return sys.executable


def _assert_phase2_schema(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        required_tables = {
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


def _verify_fresh_migration(python: str, temporary: Path) -> None:
    database = temporary / "fresh.db"
    env = os.environ.copy()
    env["QWR_DATABASE_URL"] = f"sqlite:///{database.as_posix()}"
    _run([python, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, env=env)
    _assert_phase2_schema(database)


def _create_legacy_phase1_database(path: Path) -> None:
    # This is intentionally the old Phase 1 audit shape. Other Phase 1 tables are
    # allowed to be absent here because 0002 uses current metadata to create any
    # missing tables while separately upgrading the existing audit table.
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE alembic_version (
                version_num VARCHAR(32) NOT NULL PRIMARY KEY
            );
            INSERT INTO alembic_version(version_num) VALUES ('0001_phase1');

            CREATE TABLE audit_records (
                audit_id VARCHAR(36) NOT NULL PRIMARY KEY,
                timestamp DATETIME NOT NULL,
                actor_type VARCHAR(64) NOT NULL,
                actor_id VARCHAR(128) NOT NULL,
                action VARCHAR(128) NOT NULL,
                resource_type VARCHAR(64) NOT NULL,
                resource_id VARCHAR(128) NOT NULL,
                details JSON NOT NULL,
                incident_id VARCHAR(36)
            );
            """
        )


def _verify_phase1_upgrade(python: str, temporary: Path) -> None:
    database = temporary / "legacy-phase1.db"
    _create_legacy_phase1_database(database)
    env = os.environ.copy()
    env["QWR_DATABASE_URL"] = f"sqlite:///{database.as_posix()}"
    _run([python, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, env=env)
    _assert_phase2_schema(database)


def _verify_action_surface(python: str) -> None:
    code = (
        "from app.services.action_registry import ACTION_REGISTRY; "
        "expected={'restart_quietward_demo_service'}; "
        "actual=set(ACTION_REGISTRY); "
        "assert actual == expected, f'unexpected executable actions: {sorted(actual)}'; "
        "print('allowlisted executable actions:', sorted(actual))"
    )
    _run([python, "-c", code], cwd=BACKEND)


def _verify_quietward(quietward_repo: Path) -> None:
    if not (quietward_repo / "src" / "quietward").is_dir():
        raise RuntimeError(f"not a QuietWard checkout: {quietward_repo}")
    env = os.environ.copy()
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(quietward_repo / "src") + (os.pathsep + existing if existing else "")
    python = sys.executable
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

    python = _python()
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
    _run([npm, "run", "typecheck"], cwd=FRONTEND)
    _run([npm, "run", "build"], cwd=FRONTEND)
    if not args.skip_npm_audit:
        _run([npm, "audit", "--audit-level=high"], cwd=FRONTEND)

    if args.quietward_repo is not None:
        _verify_quietward(args.quietward_repo.resolve())

    print("\nV1 STATIC/LOCAL RELEASE GATE: PASS")
    if args.quietward_repo is None:
        print("Companion QuietWard suite: NOT RUN (pass --quietward-repo PATH to include it)")
    print("The live two-repository HTTP demo remains a separate acceptance check.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
