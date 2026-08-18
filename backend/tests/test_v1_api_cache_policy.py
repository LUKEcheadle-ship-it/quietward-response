from __future__ import annotations


def test_v1_api_responses_are_not_cacheable(client) -> None:
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert "no-store" in health.headers["cache-control"]

    incidents = client.get("/api/v1/incidents")
    assert incidents.status_code == 200
    assert "no-store" in incidents.headers["cache-control"]
