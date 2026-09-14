from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select, update

from app.config import Settings
from app.database.models import ActionRecord, ApprovalRecord, AuditRecord, EventRecord, IncidentRecord
from test_phase2_secure_integration import _enroll, _post_signed_json, _quietward_event


def test_named_analyst_cannot_spoof_identity_or_replace_agent_auth(client, event_factory):
    # Public synthetic credential, used only in this test's temporary database.
    token = 'synthetic-review-analyst-credential-0123456789'
    client.app.state.settings.analyst_token_hashes = {'alice': hashlib.sha256(token.encode()).hexdigest()}
    auth = {'Authorization': f'Bearer {token}', 'X-Actor-ID': 'forged-admin'}
    assert client.get('/api/v1/access').json()['authentication_required'] is True
    for path in ['/api/v1/incidents/page', '/api/v1/overview/bridge', '/api/v1/agents', '/api/v1/audit/verify']:
        assert client.get(path).status_code == 401
        assert client.get(path, headers={'Authorization': 'Bearer ' + 'x'*40}).status_code == 401
        assert client.get(path, headers=auth).status_code == 200
    preflight = client.options('/api/v1/incidents/page', headers={
        'Origin': 'http://localhost:3001', 'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'authorization'})
    assert preflight.status_code == 200
    payload = event_factory(host_id='auth-host', event_type='quietward_demo_service_unhealthy', category='operational')
    assert client.post('/api/v1/events', json=payload).status_code == 401
    posted = client.post('/api/v1/events', json=payload, headers=auth)
    assert posted.status_code == 201
    incident_id = posted.json()['incident_id']
    enrolled = _enroll(client, host_id='auth-host')
    quietward = _quietward_event('auth-host')
    assert client.post('/api/v1/events', json=quietward, headers=auth).status_code == 401
    assert _post_signed_json(client, enrolled, '/api/v1/events', quietward).status_code == 201
    created = client.post(f'/api/v1/incidents/{incident_id}/actions', headers=auth, json={
        'target_agent_id': enrolled['agent_id'], 'target_host_id': 'auth-host',
        'action_type': 'restart_quietward_demo_service', 'parameters': {}})
    assert created.status_code == 201, created.text
    action_id = created.json()['action_id']
    assert created.json()['requested_by'] == 'alice'
    assert client.post(f'/api/v1/actions/{action_id}/approve', json={'reason': 'test'}).status_code == 401
    assert client.post(f'/api/v1/actions/{action_id}/approve', json={'reason': 'test'}, headers=auth).status_code == 200
    with client.app.state.database.session_factory() as session:
        action = session.get(ActionRecord, action_id)
        assert session.get(ApprovalRecord, action.approval_id).approved_by == 'alice'
        approval = session.scalar(select(AuditRecord).where(AuditRecord.resource_id == action_id,
                                                          AuditRecord.action == 'response_action_approved'))
        assert approval.actor_id == 'alice'
    client.app.state.settings.analyst_token_hashes = {'alice': hashlib.sha256(b'rotated-synthetic-credential-0123456789').hexdigest()}
    assert client.get('/api/v1/incidents/page', headers=auth).status_code == 401


def test_non_loopback_requires_named_analysts():
    with pytest.raises(ValueError, match='QWR_ANALYST_TOKEN_HASHES'):
        Settings(_env_file=None, api_host='0.0.0.0', enrollment_token='synthetic-long-enrollment-token')
    with pytest.raises(ValueError, match='distinct'):
        Settings(_env_file=None, analyst_token_hashes={'alice': '0'*64, 'bob': '0'*64})


def test_incident_pagination_ties_filters_and_invalid_cursor(client, event_factory):
    now = datetime.now(timezone.utc)
    with client.app.state.database.session_factory() as session:
        for index in range(121):
            session.add(IncidentRecord(incident_id=str(uuid4()), title=f'Review incident {index}',
                severity='high' if index % 2 else 'low', status='new', first_event_at=now,
                last_event_at=now, created_at=now, updated_at=now))
        session.commit()
    ids = []
    cursor = None
    while True:
        params = {'limit': 37}
        if cursor: params['cursor'] = cursor
        response = client.get('/api/v1/incidents/page', params=params)
        assert response.status_code == 200
        page = response.json()
        assert page['total'] == 121
        ids.extend(row['incident_id'] for row in page['items'])
        cursor = page['next_cursor']
        if not cursor: break
    assert len(ids) == len(set(ids)) == 121
    assert ids == sorted(ids, reverse=True)
    assert client.get('/api/v1/incidents/page', params={'severity': 'high', 'status': 'new'}).json()['total'] == 60
    assert client.get('/api/v1/incidents/page', params={'search': '%'}).json()['total'] == 0
    assert client.get('/api/v1/incidents/page', params={'search': ids[0]}).json()['total'] == 1
    event = client.post('/api/v1/events', json=event_factory(host_id='filter-host')).json()
    page = client.get('/api/v1/incidents/page', params={'host': 'filter-host'}).json()
    assert page['total'] == 1 and page['items'][0]['incident_id'] == event['incident_id']
    for malformed in ['!', 'abc', base64.urlsafe_b64encode(json.dumps([]).encode()).decode()]:
        assert client.get('/api/v1/incidents/page', params={'cursor': malformed}).status_code == 422


def test_bridge_uses_receipt_time_and_reports_unknown_queue(client, event_factory):
    assert client.get('/api/v1/overview/bridge').json()['state'] == 'no_data'
    event = client.post('/api/v1/events', json=event_factory()).json()
    now = datetime.now(timezone.utc)
    with client.app.state.database.session_factory() as session:
        session.execute(update(EventRecord).where(EventRecord.event_id == event['event_id']).values(
            source='quietward', received_at=now, occurred_at=now-timedelta(days=10)))
        session.commit()
    status = client.get('/api/v1/overview/bridge').json()
    assert status['state'] == 'recent' and status['received_last_24h'] == 1
    assert status['pending_handoffs'] is None
    assert 'host_id' not in status and 'evidence' not in status
    with client.app.state.database.session_factory() as session:
        session.execute(update(EventRecord).values(received_at=now-timedelta(days=2)))
        session.commit()
    status = client.get('/api/v1/overview/bridge').json()
    assert status['state'] == 'idle' and status['received_last_24h'] == 0
