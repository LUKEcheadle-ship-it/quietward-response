#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Any, Iterable

from sqlalchemy import select

from app.config import Settings
from app.database.models import ActionRecord, ApprovalRecord, AuditRecord, EventRecord
from app.database.session import Database
from app.services.redaction import redact_sensitive, redact_sensitive_text


@dataclass(frozen=True, slots=True)
class Finding:
    table: str
    record_id: str
    field: str


def _changed(value: Any) -> bool:
    return redact_sensitive(value) != value


def _changed_text(value: str | None) -> bool:
    return value is not None and redact_sensitive_text(value) != value


def scan_session(session, *, max_rows_per_table: int = 100_000) -> list[Finding]:
    findings: list[Finding] = []

    events: Iterable[EventRecord] = session.scalars(
        select(EventRecord).order_by(EventRecord.received_at.desc()).limit(max_rows_per_table)
    )
    for row in events:
        if _changed(row.payload or {}):
            findings.append(Finding("events", row.event_id, "payload"))
        if _changed(row.normalized or {}):
            findings.append(Finding("events", row.event_id, "normalized"))
        if _changed_text(row.summary):
            findings.append(Finding("events", row.event_id, "summary"))

    actions: Iterable[ActionRecord] = session.scalars(
        select(ActionRecord).order_by(ActionRecord.requested_at.desc()).limit(max_rows_per_table)
    )
    for row in actions:
        if _changed(row.result or {}):
            findings.append(Finding("actions", row.action_id, "result"))
        if _changed(row.evidence or {}):
            findings.append(Finding("actions", row.action_id, "evidence"))
        if _changed_text(row.error):
            findings.append(Finding("actions", row.action_id, "error"))

    approvals: Iterable[ApprovalRecord] = session.scalars(
        select(ApprovalRecord).order_by(ApprovalRecord.requested_at.desc()).limit(max_rows_per_table)
    )
    for row in approvals:
        if _changed_text(row.rejection_reason):
            findings.append(Finding("approvals", row.approval_id, "rejection_reason"))

    audits: Iterable[AuditRecord] = session.scalars(
        select(AuditRecord).order_by(AuditRecord.timestamp.desc()).limit(max_rows_per_table)
    )
    for row in audits:
        if _changed(row.details or {}):
            findings.append(Finding("audit_records", row.audit_id, "details"))

    return findings


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scan QuietWard Response durable event/action/approval/audit fields for "
            "credential-like values that the current redaction policy would remove."
        )
    )
    parser.add_argument(
        "--database-url",
        help="Database URL. Defaults to the normal QWR_DATABASE_URL configuration.",
    )
    parser.add_argument(
        "--max-rows-per-table",
        type=int,
        default=100_000,
        help="Bounded newest-row scan per table (default 100000).",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    if not 1 <= args.max_rows_per_table <= 1_000_000:
        raise SystemExit("--max-rows-per-table must be between 1 and 1000000")
    database_url = args.database_url or Settings().database_url
    database = Database(database_url)
    try:
        with database.session_factory() as session:
            findings = scan_session(session, max_rows_per_table=args.max_rows_per_table)
    finally:
        database.dispose()

    if findings:
        print("SENSITIVE PERSISTENCE AUDIT: FAIL")
        print(f"findings={len(findings)}")
        for item in findings[:200]:
            print(f"{item.table}:{item.record_id}:{item.field}")
        if len(findings) > 200:
            print(f"... {len(findings) - 200} additional finding(s) omitted")
        print("Secret values are intentionally never printed by this audit.")
        return 1

    print("SENSITIVE PERSISTENCE AUDIT: PASS")
    print("credential_like_persisted_values=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
