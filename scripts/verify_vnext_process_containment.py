#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from evidence_store import EvidenceStore, is_process_evidence_handle
from process_containment import (
    ProcessContainmentError,
    _protected_reason,
    terminate_evidence_process,
)
from response_agent_diagnostics import collect_process_diagnostic


EVIDENCE_KEY = b"quietward-response-vnext-live-test-key-material-0001"
PROCESS_DISCOVERY_TIMEOUT_SECONDS = 5.0
PROCESS_EXIT_TIMEOUT_SECONDS = 5.0


def _process_row(pid: int) -> dict[str, object] | None:
    deadline = time.monotonic() + PROCESS_DISCOVERY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        result = collect_process_diagnostic()
        rows = result.get("processes")
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) and int(row.get("pid", -1)) == pid:
                    return row
        time.sleep(0.05)
    return None


def _stop_disposable(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=PROCESS_EXIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=PROCESS_EXIT_TIMEOUT_SECONDS)


def _spawn_disposable() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(120)",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _verify_successful_evidence_bound_termination(state_dir: Path) -> None:
    process = _spawn_disposable()
    try:
        row = _process_row(process.pid)
        if row is None:
            raise RuntimeError("disposable child process did not appear in bounded diagnostic inventory")
        handle = EvidenceStore(state_dir, EVIDENCE_KEY).record_process(row)
        if handle is None or not is_process_evidence_handle(handle):
            raise RuntimeError("disposable child process did not receive a valid evidence handle")

        result = terminate_evidence_process(state_dir, EVIDENCE_KEY, handle)
        try:
            process.wait(timeout=PROCESS_EXIT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("containment returned but disposable process remained alive") from exc

        if result.get("containment_type") != "terminate_evidence_process":
            raise RuntimeError(f"unexpected containment result: {result!r}")
        if result.get("confirmed_original_process_exited") is not True:
            raise RuntimeError(f"containment did not confirm original process exit: {result!r}")
        if result.get("execution_time_identity_revalidated") is not True:
            raise RuntimeError(f"containment skipped identity revalidation: {result!r}")
        if result.get("arbitrary_pid_accepted") is not False:
            raise RuntimeError(f"containment exposed arbitrary PID targeting: {result!r}")
        if result.get("arbitrary_command_execution") is not False:
            raise RuntimeError(f"containment exposed arbitrary command execution: {result!r}")
    finally:
        _stop_disposable(process)


def _verify_stale_process_handle_fails_closed(state_dir: Path) -> None:
    process = _spawn_disposable()
    try:
        row = _process_row(process.pid)
        if row is None:
            raise RuntimeError("stale-handle test child was not observable")
        handle = EvidenceStore(state_dir, EVIDENCE_KEY).record_process(row)
        if handle is None:
            raise RuntimeError("stale-handle test could not record evidence")
        _stop_disposable(process)
        try:
            terminate_evidence_process(state_dir, EVIDENCE_KEY, handle)
        except ProcessContainmentError as exc:
            message = str(exc).casefold()
            if "no longer running" not in message and "instance changed" not in message:
                raise RuntimeError(f"stale handle failed for the wrong reason: {exc}") from exc
        else:
            raise RuntimeError("stale process evidence handle was accepted after target exit")
    finally:
        _stop_disposable(process)


def _verify_agent_process_protection_rule() -> None:
    reason = _protected_reason(
        {
            "pid": os.getpid(),
            "parent_pid": os.getppid(),
            "image": Path(sys.executable).name or "python",
        }
    )
    if not reason or "protected" not in reason.casefold():
        raise RuntimeError("Response verifier/self process protection rule did not hold")


def main() -> int:
    if not (sys.platform.startswith("linux") or os.name == "nt"):
        print("VNEXT LIVE PROCESS CONTAINMENT: SKIP (supported only on Linux and Windows)")
        return 0

    with tempfile.TemporaryDirectory(prefix="qwr-vnext-containment-") as temporary:
        state_dir = Path(temporary).resolve()
        _verify_successful_evidence_bound_termination(state_dir)
        _verify_stale_process_handle_fails_closed(state_dir)
        _verify_agent_process_protection_rule()

    print("VNEXT LIVE PROCESS CONTAINMENT: PASS")
    print("- disposable evidence-bound process terminated and exit confirmed")
    print("- stale evidence handle failed closed")
    print("- Response verifier/self process protection rule held")
    print("- no arbitrary PID or arbitrary command surface used")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
