from __future__ import annotations


def test_enrollment_secret_response_is_not_cacheable(client) -> None:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": "no-store-host",
            "display_name": "no-store-agent",
            "agent_version": "test",
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["secret"]
    assert "no-store" in response.headers["cache-control"]
    assert response.headers["pragma"] == "no-cache"
