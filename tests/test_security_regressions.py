import runpy
from pathlib import Path

import pytest
import redis
import app as app_module


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setitem(app_module.app.config, 'TESTING', True)
    monkeypatch.setattr(app_module.limiter, 'enabled', False)
    monkeypatch.setattr(app_module, 'check_hibp', lambda password: 0)
    with app_module.app.test_client() as test_client:
        yield test_client


@pytest.mark.parametrize('payload', [[], ['x'], 'x', 1, True, None])
def test_non_object_json_returns_400(client, payload):
    import json
    response = client.post('/api/evaluate', data=json.dumps(payload),
                           content_type='application/json')
    assert response.status_code == 400
    assert response.get_json()['error'] == 'Request body must be a JSON object'
    assert response.headers['Cache-Control'] == 'no-store'


@pytest.mark.parametrize('method,path,payload,status', [
    ('get', '/api/generate', None, 200),
    ('post', '/api/evaluate', {'password': 'audit-example-only'}, 200),
    ('post', '/api/evaluate', {}, 400),
    ('get', '/api/not-a-route', None, 404),
])
def test_api_responses_are_not_stored(client, method, path, payload, status):
    kwargs = {'json': payload} if payload is not None else {}
    response = getattr(client, method)(path, **kwargs)
    assert response.status_code == status
    assert response.headers['Cache-Control'] == 'no-store'


@pytest.mark.parametrize('fail', [False, True])
def test_redis_logs_do_not_disclose_credentials(monkeypatch, capsys, fail):
    secret = 'AUDIT_DUMMY_SECRET'
    monkeypatch.setenv('REDIS_URL', f'redis://:{secret}@127.0.0.1:6379/0')

    def fake_ping(self, *args, **kwargs):
        if fail:
            raise RuntimeError(f'Synthetic failure containing {secret}')
        return True

    monkeypatch.setattr(redis.Redis, 'ping', fake_ping)
    runpy.run_path(str(Path(app_module.__file__).resolve()),
                   run_name='audit_redis_logging')
    captured = capsys.readouterr()
    assert 'configured Redis instance' in captured.out
    assert secret not in captured.out + captured.err
