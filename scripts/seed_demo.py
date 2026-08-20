#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import NAMESPACE_URL, uuid4, uuid5


def build_demo_events(
    *, base_time: datetime | None = None, batch_id: str | None = None
) -> list[dict[str, Any]]:
    base = base_time or datetime.now(timezone.utc).replace(microsecond=0)
    batch = batch_id or str(uuid4())

    def event(
        scenario: str,
        offset: int,
        host_id: str,
        event_type: str,
        category: str,
        severity: str,
        summary: str,
        **sections: Any,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "event_id": str(uuid5(NAMESPACE_URL, f"quietward-response-demo:{batch}:{scenario}:{offset}")),
            "source": "quietward-demo",
            "source_version": "1.0.0",
            "host_id": host_id,
            "host_name": host_id,
            "timestamp": (base + timedelta(seconds=offset)).isoformat(),
            "event_type": event_type,
            "category": category,
            "severity": severity,
            "confidence": 0.82,
            "summary": summary,
            "evidence": {"synthetic": True, "scenario": scenario},
            "metadata": {"operating_system": "Synthetic Linux", "demo": True},
        }
        payload.update(sections)
        return payload

    executable = "/opt/demo/telemetry-helper"
    persistence = [
        event("persistence", 0, "demo-endpoint-01", "unknown_executable_created", "persistence", "high", "Unknown executable created in an application directory", file={"path": executable, "sha256": "demo-sha256-not-a-real-sample"}),
        event("persistence", 8, "demo-endpoint-01", "scheduled_task_created", "persistence", "high", "New scheduled task references the unknown executable", file={"path": executable}, persistence={"mechanism": "scheduled_task", "name": "DemoTelemetry"}),
        event("persistence", 13, "demo-endpoint-01", "process_launched", "persistence", "high", "Scheduled executable launched", process={"pid": 4242, "path": executable, "parent_pid": 900}),
        event("persistence", 16, "demo-endpoint-01", "outbound_connection_initiated", "persistence", "critical", "Executable initiated an outbound connection", process={"pid": 4242, "path": executable}, network={"destination_address": "198.51.100.42", "destination_port": 443}),
    ]
    exposed = [
        event("exposed-service", 60, "demo-server-02", "new_listener_detected", "network", "high", "A new listening service was detected", process={"pid": 5151, "path": "/usr/local/bin/demo-api"}, network={"bind_address": "0.0.0.0", "port": 9443}),
        event("exposed-service", 65, "demo-server-02", "wildcard_bind_detected", "network", "high", "The new listener is bound to all interfaces", process={"pid": 5151, "path": "/usr/local/bin/demo-api"}, network={"bind_address": "0.0.0.0", "port": 9443}),
        event("exposed-service", 71, "demo-server-02", "unexpected_service_process", "network", "medium", "Listener process is absent from the approved service inventory", process={"pid": 5151, "path": "/usr/local/bin/demo-api"}, network={"bind_address": "0.0.0.0", "port": 9443}),
    ]
    operational = [
        event("disk-exhaustion", 120, "demo-storage-03", "disk_usage_rising", "operational", "medium", "Disk usage crossed the warning threshold", evidence={"synthetic": True, "scenario": "disk-exhaustion", "usage_percent": 88}),
        event("disk-exhaustion", 155, "demo-storage-03", "service_health_degraded", "operational", "high", "Database writes began failing as free space declined", evidence={"synthetic": True, "scenario": "disk-exhaustion", "usage_percent": 96}),
        event("disk-exhaustion", 190, "demo-storage-03", "service_unavailable", "operational", "critical", "Dependent service became unavailable", evidence={"synthetic": True, "scenario": "disk-exhaustion", "usage_percent": 99}),
    ]
    return persistence + exposed + operational


def seed(api_url: str) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for payload in build_demo_events():
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            f"{api_url.rstrip('/')}/api/v1/events",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                results.append(json.loads(response.read()))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"event ingestion failed ({exc.code}): {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"cannot reach QuietWard Response at {api_url}: {exc}") from exc
    return {
        "events_submitted": len(results),
        "incidents_created_or_updated": len({result["incident_id"] for result in results}),
        "incident_ids": sorted({result["incident_id"] for result in results}),
        "actions_executed": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed safe synthetic v1 investigation incidents")
    parser.add_argument("--api-url", default="http://localhost:8002")
    args = parser.parse_args()
    try:
        result = seed(args.api_url)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
