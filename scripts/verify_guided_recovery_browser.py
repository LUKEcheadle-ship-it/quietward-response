#!/usr/bin/env python3
"""Real named-analyst browser acceptance against isolated synthetic state.

Runs only local API/frontend children. Never starts an endpoint agent, performs a
remediation, fetches an evidence reference, or creates an external ticket.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
API = "http://127.0.0.1:8002"
WEB = "http://127.0.0.1:3001"
NOTE = "Synthetic owner-reviewed recovery evidence confirms the explicitly scoped outcome."


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "posix":
        raise SystemExit("Browser harness uses POSIX process-group cleanup; use the native backend suite on Windows.")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    for port in (8002, 3001):
        with socket.socket() as guard:
            guard.bind(("127.0.0.1", port))  # Do not reuse or stop an existing service.
    tokens = {actor: secrets.token_urlsafe(40) for actor in ("operator", "approver", "reviewer")}
    children = []
    streams = []
    pages = []
    errors = []
    with tempfile.TemporaryDirectory(prefix="qwr-guided-browser-") as temporary:
        database = Path(temporary) / "synthetic.db"
        env = os.environ | {
            "QWR_ENVIRONMENT": "development", "QWR_API_HOST": "127.0.0.1", "QWR_API_PORT": "8002",
            "QWR_DATABASE_URL": f"sqlite:///{database.as_posix()}", "QWR_SEED_DEMO": "false",
            "QWR_ENROLLMENT_TOKEN": secrets.token_urlsafe(40), "NEXT_TELEMETRY_DISABLED": "1",
            "QWR_ANALYST_TOKEN_HASHES": json.dumps({actor: digest(token) for actor, token in tokens.items()}),
            "QWR_CORS_ORIGINS": json.dumps([WEB]),
        }

        def request(path, method="GET", payload=None, actor="operator"):
            data = json.dumps(payload).encode() if payload is not None else None
            req = urllib.request.Request(API + path, data=data, method=method,
                  headers={"Authorization": "Bearer " + tokens[actor], "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.load(response)

        def start(command, cwd, filename):
            stream = (out / filename).open("w", encoding="utf-8")
            streams.append(stream)
            child = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            children.append(child)
            return child

        def ready(url, child):
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    raise RuntimeError("Qualification service exited before readiness")
                try:
                    with urllib.request.urlopen(url, timeout=2) as response:
                        if response.status == 200:
                            return
                except OSError:
                    pass
                time.sleep(.2)
            raise RuntimeError("Qualification service readiness timed out")

        def seed(category, host):
            return request("/api/v1/events", "POST", {
                "schema_version": "1.0", "event_id": str(uuid4()), "source": "qualification-sensor",
                "source_version": "1", "host_id": host, "host_name": host + ".example.test",
                "timestamp": now(), "event_type": "synthetic_recovery_observation", "category": category,
                "severity": "medium", "confidence": .7, "summary": "Synthetic guided recovery qualification",
                "evidence": {"synthetic": True}, "metadata": {"operating_system": "Synthetic"},
            })["incident_id"]

        def sign_in(browser, incident_id, actor):
            context = browser.new_context(viewport={"width": 1500, "height": 1100})
            page = context.new_page(); pages.append(page)
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(WEB + f"/incidents/{incident_id}", wait_until="networkidle")
            page.get_by_label("Analyst credential", exact=True).fill(tokens[actor])
            page.get_by_role("button", name="Sign in", exact=True).click()
            expect(page.get_by_role("heading", name="Guided resolution", exact=True)).to_be_visible(timeout=30000)
            return page

        def start_plan(page):
            form = page.get_by_role("button", name="Request recovery approval", exact=True).locator("xpath=ancestor::form")
            form.get_by_label("Baseline artifact SHA-256", exact=True).fill(digest("baseline"))
            form.get_by_label("Existing change or incident ticket", exact=True).fill("SYNTHETIC-TICKET-1")
            form.get_by_label("Baseline evidence summary", exact=True).fill(NOTE)
            form.get_by_label("Owner-approved rollback plan", exact=True).fill("The authorized owner uses the reviewed rollback while preserving original evidence.")
            form.get_by_role("button", name="Request recovery approval", exact=True).click()
            expect(page.get_by_test_id("recovery-state")).to_have_text("awaiting approval")

        def fill_evidence(form, suffix):
            form.get_by_label("Evidence artifact SHA-256", exact=True).fill(digest(suffix))
            form.get_by_label("Evidence reference", exact=True).fill("SYNTHETIC-" + suffix)
            form.get_by_label("Observation time (with timezone)", exact=True).fill(now())
            form.get_by_label("Evidence and outcome note", exact=True).fill(NOTE)

        try:
            subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT / "backend", env=env, check=True, timeout=40)
            backend = start([sys.executable, "-m", "uvicorn", "app.main:runtime_app", "--factory", "--host", "127.0.0.1", "--port", "8002"], ROOT / "backend", "backend.log")
            ready(API + "/health", backend)
            frontend = start(["node", str(ROOT / "frontend/node_modules/next/dist/bin/next"), "start", "-H", "127.0.0.1", "-p", "3001"], ROOT / "frontend", "frontend.log")
            ready(WEB + "/", frontend)
            identifier = seed("identity", "synthetic-recovery-host")
            escalation_id = seed("operational", "synthetic-escalation-host")
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True, executable_path=os.environ.get("CHROMIUM_PATH"))
                try:
                    operator = sign_in(browser, identifier, "operator")
                    start_plan(operator)
                    expect(operator.get_by_role("button", name="Approve recovery plan", exact=True)).to_be_disabled()
                    approver = sign_in(browser, identifier, "approver")
                    approver.get_by_label("Independent approval rationale", exact=True).fill(NOTE)
                    approver.get_by_role("button", name="Approve recovery plan", exact=True).click()
                    expect(approver.get_by_test_id("recovery-state")).to_have_text("approved")
                    expect(approver.get_by_role("button", name="Record checkpoint evidence", exact=True)).to_be_disabled()
                    operator.get_by_role("button", name="Refresh recovery", exact=True).click()
                    expect(operator.get_by_test_id("recovery-state")).to_have_text("approved")
                    for index, title in enumerate(("Verify the account and provider", "Contain suspicious sessions", "Recover authentication", "Verify restored access")):
                        form = operator.get_by_role("button", name="Record checkpoint evidence", exact=True).locator("xpath=ancestor::form")
                        expect(form.get_by_role("heading", name="Record checkpoint: " + title, exact=True)).to_be_visible()
                        fill_evidence(form, f"checkpoint-{index}")
                        form.get_by_role("button", name="Record checkpoint evidence", exact=True).click()
                        expect(operator.get_by_role("heading", name=f"{index + 1}. {title} — done", exact=True)).to_be_visible()
                    expect(operator.get_by_test_id("recovery-state")).to_have_text("awaiting verification")
                    expect(operator.get_by_role("button", name="Verify recorded recovery", exact=True)).to_be_disabled()
                    reviewer = sign_in(browser, identifier, "reviewer")
                    form = reviewer.get_by_role("button", name="Verify recorded recovery", exact=True).locator("xpath=ancestor::form")
                    fill_evidence(form, "independent-verification")
                    form.get_by_role("button", name="Verify recorded recovery", exact=True).click()
                    expect(reviewer.get_by_test_id("recovery-state")).to_have_text("verified")
                    reviewer.get_by_label("Final incident closure rationale", exact=True).fill(NOTE)
                    reviewer.get_by_role("button", name="Close independently verified recovery", exact=True).click()
                    expect(reviewer.get_by_role("combobox", name="Status", exact=True)).to_have_value("resolved")
                    reviewer.get_by_role("heading", name="Guided resolution", exact=True).scroll_into_view_if_needed()
                    reviewer.screenshot(path=str(out / "verified-recovery.png"), full_page=True)
                    assert request(f"/api/v1/incidents/{identifier}")["status"] == "resolved"

                    operator_escalation = sign_in(browser, escalation_id, "operator")
                    start_plan(operator_escalation)
                    operator_escalation.get_by_text("Escalate blocked or unsafe recovery", exact=True).click()
                    form = operator_escalation.get_by_role("button", name="Record escalation", exact=True).locator("xpath=ancestor::form")
                    form.get_by_label("Assigned named analyst", exact=True).fill("reviewer")
                    form.get_by_label("Existing escalation ticket", exact=True).fill("SYNTHETIC-ESCALATION-1")
                    form.get_by_label("Follow-up due (timezone required, within seven days)", exact=True).fill((datetime.now(timezone.utc) + timedelta(days=1)).isoformat())
                    form.get_by_label("Reason and required assistance", exact=True).fill(NOTE)
                    form.get_by_role("button", name="Record escalation", exact=True).click()
                    expect(operator_escalation.get_by_test_id("recovery-state")).to_have_text("escalated")
                    expect(operator_escalation.get_by_role("button", name="Close independently verified recovery", exact=True)).to_be_disabled()
                    recipient = sign_in(browser, escalation_id, "reviewer")
                    recipient.get_by_label("Escalation acknowledgement", exact=True).fill(NOTE)
                    recipient.get_by_role("button", name="Acknowledge escalation", exact=True).click()
                    expect(recipient.get_by_text("Acknowledged by reviewer; incident remains unresolved.", exact=True)).to_be_visible()
                    recipient.screenshot(path=str(out / "acknowledged-escalation.png"), full_page=True)
                    assert request(f"/api/v1/incidents/{escalation_id}")["status"] == "investigating"
                    assert not errors, errors
                except BaseException:
                    for i, page in enumerate(pages):
                        if not page.is_closed():
                            page.screenshot(path=str(out / f"failure-{i}.png"), full_page=True)
                    raise
                finally:
                    browser.close()
            assert request("/api/v1/audit/verify")["valid"] is True
            with sqlite3.connect(database) as connection:
                assert connection.execute("SELECT COUNT(*) FROM actions").fetchone()[0] == 0
                workflows = connection.execute("SELECT state, COUNT(*) FROM resolution_workflows GROUP BY state").fetchall()
            source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
            receipt = {"decision": "PASS", "source_sha": source, "source_dirty": dirty,
                       "synthetic_data_only": True, "separate_named_browser_sessions": 3,
                       "operator_cannot_self_approve_or_verify": True, "non_owner_cannot_record_work": True,
                       "verified_recovery_closed": True, "acknowledged_escalation_remains_unresolved": True,
                       "audit_chain_valid": True, "endpoint_agents_started": 0, "endpoint_actions_created": 0,
                       "external_tickets_created": 0, "artifact_contents_verified_by_server": False,
                       "verification_kind": "independent_human_attestation", "javascript_errors": errors,
                       "workflow_states": workflows}
            (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            print("Guided recovery real-browser acceptance: PASS")
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)
            for stream in streams: stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
