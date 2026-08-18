from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor


def test_concurrent_http_events_preserve_single_audit_chain(client, event_factory) -> None:
    payloads = [
        event_factory(
            index=index,
            host_id=f"concurrency-host-{index}",
            event_type="process_observed",
        )
        for index in range(8)
    ]

    def submit(payload):
        return client.post("/api/v1/events", json=payload)

    with ThreadPoolExecutor(max_workers=8) as executor:
        responses = list(executor.map(submit, payloads))

    assert [response.status_code for response in responses] == [201] * len(payloads)
    verification = client.get("/api/v1/audit/verify")
    assert verification.status_code == 200
    body = verification.json()
    assert body["valid"] is True, body
    assert body["entries_checked"] >= len(payloads) * 2
