from __future__ import annotations

import pytest

from test_v1_auth_transactions import _enroll, _signed_event_headers


def test_non_ascii_enrollment_token_is_rejected(client):
    response = client.post(
        '/api/v1/agents/enroll',
        headers={b'X-QWR-Enrollment-Token': b'invalid-\xff-token'},
        json={'host_id': 'encoding-host', 'display_name': 'encoding-agent'},
    )
    assert response.status_code == 401
    assert response.json()['detail']['code'] == 'invalid_enrollment_token'
    assert client.get('/api/v1/agents').json() == []


@pytest.mark.parametrize('header,code', [
    ('X-QWR-Key-ID', 'invalid_key_id'),
    ('X-QWR-Signature', 'invalid_signature'),
])
def test_non_ascii_agent_credentials_are_rejected(client, event_factory, header, code):
    enrollment = _enroll(client, 'encoding-host')
    payload = event_factory(host_id='encoding-host', source='quietward')
    body, headers = _signed_event_headers(enrollment, payload)
    wire_headers = {key.encode(): value.encode() for key, value in headers.items()}
    wire_headers[header.encode()] = b'invalid-\xff-credential'
    response = client.post('/api/v1/events', content=body, headers=wire_headers)
    assert response.status_code == 401
    assert response.json()['detail']['code'] == code
    assert client.get('/health').status_code == 200
