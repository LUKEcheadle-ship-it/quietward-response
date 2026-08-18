#!/usr/bin/env python3
"""Submit safe synthetic scenarios to a running QuietWard Response API."""
import argparse
import json
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4


def event(host_id: str, host_name: str, when: datetime, event_type: str, category: str, severity: str, summary: str, **evidence):
    return {
        "schema_version": "1.0", "event_id": str(uuid4()), "source": "quietward-demo", "source_version": "1.0.0",
        "host_id": host_id, "host_name": host_name, "timestamp": when.isoformat(), "event_type": event_type,
        "category": category, "severity": severity, "confidence": evidence.pop("confidence", 85), "summary": summary,
        "evidence": {"synthetic": True, "scenario": evidence.pop("scenario")}, "metadata": {"operating_system": evidence.pop("os", "Windows 11")}, **evidence,
    }


def scenarios():
    base = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=2)
    executable = "C:/ProgramData/QuietWardDemo/update-helper.exe"
    return {
        "Suspicious persistence": [
            event("demo-ws-01", "finance-ws-01", base, "file.created", "persistence", "high", "Unknown executable created", scenario="persistence", file={"path": executable, "sha256": "synthetic-demo-sha256"}),
            event("demo-ws-01", "finance-ws-01", base + timedelta(seconds=8), "scheduled_task.created", "persistence", "high", "Scheduled task created for unknown executable", scenario="persistence", file={"path": executable}, persistence={"mechanism": "scheduled_task", "name": "DemoTelemetry"}),
            event("demo-ws-01", "finance-ws-01", base + timedelta(seconds=11), "process.started", "execution", "high", "Unknown executable launched", scenario="persistence", process={"pid": 4242, "executable": executable}, file={"path": executable}),
            event("demo-ws-01", "finance-ws-01", base + timedelta(seconds=14), "network.connection", "network", "critical", "Process initiated an outbound connection", scenario="persistence", process={"pid": 4242, "executable": executable}, network={"destination_address": "198.51.100.42", "destination_port": 443}),
        ],
        "Exposed service": [
            event("demo-srv-02", "staging-api-02", base + timedelta(seconds=30), "listener.detected", "network", "medium", "New listener detected", scenario="listener", process={"pid": 811, "executable": "/opt/demo-service"}, network={"bind_address": "0.0.0.0", "local_port": 9080}, os="Linux"),
            event("demo-srv-02", "staging-api-02", base + timedelta(seconds=35), "listener.wildcard_bind", "network", "high", "Service listening on wildcard address", scenario="listener", process={"pid": 811, "executable": "/opt/demo-service"}, network={"bind_address": "0.0.0.0", "local_port": 9080}, os="Linux"),
            event("demo-srv-02", "staging-api-02", base + timedelta(seconds=39), "service.unexpected", "service", "high", "Unexpected process owns listening service", scenario="listener", process={"pid": 811, "executable": "/opt/demo-service"}, os="Linux"),
        ],
        "Operational disk incident": [
            event("demo-srv-03", "orders-db-03", base + timedelta(seconds=60), "disk.usage_rising", "availability", "medium", "Disk usage rose rapidly to 91 percent", scenario="disk", evidence={"mount": "/var", "percent": 91}, os="Linux"),
            event("demo-srv-03", "orders-db-03", base + timedelta(seconds=70), "service.failure", "availability", "high", "Database service health checks started failing", scenario="disk", evidence={"service": "orders-db"}, os="Linux"),
            event("demo-srv-03", "orders-db-03", base + timedelta(seconds=82), "service.unavailable", "availability", "critical", "Database service became unavailable", scenario="disk", evidence={"service": "orders-db"}, os="Linux"),
        ],
    }


def post(url: str, payload: dict) -> dict:
    request = Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=10) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8001/api/v1")
    args = parser.parse_args()
    for name, events in scenarios().items():
        incident_ids = []
        for payload in events:
            try:
                result = post(f"{args.base_url}/events", payload)
            except HTTPError as exc:
                raise SystemExit(f"{name} failed: HTTP {exc.code} {exc.read().decode()}") from exc
            incident_ids.append(result["incident_id"])
        if len(set(incident_ids)) != 1:
            raise SystemExit(f"{name} did not correlate into one incident: {incident_ids}")
        print(f"{name}: {len(events)} events -> incident {incident_ids[0]}")


if __name__ == "__main__":
    main()
