from __future__ import annotations


def _assert_security_headers(response) -> None:
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"


def test_v1_api_responses_are_not_cacheable_and_have_baseline_browser_headers(client) -> None:
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert "no-store" in health.headers["cache-control"]
    _assert_security_headers(health)

    incidents = client.get("/api/v1/incidents")
    assert incidents.status_code == 200
    assert "no-store" in incidents.headers["cache-control"]
    _assert_security_headers(incidents)

    # Non-v1 docs/root responses are not forced no-store, but still get the
    # low-risk browser hardening headers from the shared middleware.
    root = client.get("/")
    assert root.status_code == 200
    _assert_security_headers(root)
