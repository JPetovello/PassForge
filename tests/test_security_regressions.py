import runpy
from pathlib import Path

import pytest
import redis
import app as app_module


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(app_module.limiter, 'enabled', False)
    monkeypatch.setattr(app_module, 'fetch_hibp_range', lambda prefix: '')
    with app_module.app.test_client() as test_client:
        yield test_client


@pytest.mark.parametrize('method,path', [
    ('post', '/api/evaluate'),
    ('get', '/api/generate'),
])
def test_obsolete_sensitive_endpoints_are_removed(client, method, path):
    kwargs = {'json': {}} if method == 'post' else {}
    response = getattr(client, method)(path, **kwargs)
    assert response.status_code == 404
    assert response.headers['Cache-Control'] == 'no-store'


@pytest.mark.parametrize('path', [
    '/api/not-a-route',
])
def test_api_responses_are_not_stored(client, path):
    response = client.get(path)
    assert response.headers['Cache-Control'] == 'no-store'


def test_hibp_post_response_is_not_stored(client):
    response = client.post('/api/hibp', json={'prefix': 'ABCDE'})
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'


@pytest.mark.parametrize('fail', [False, True])
def test_redis_logs_do_not_disclose_credentials(monkeypatch, capsys, fail):
    secret = 'AUDIT_DUMMY_SECRET'
    monkeypatch.setenv(
        'REDIS_URL',
        f'redis://:{secret}@127.0.0.1:6379/0',
    )

    def fake_ping(self, *args, **kwargs):
        if fail:
            raise RuntimeError(
                f'Synthetic failure containing {secret}'
            )
        return True

    monkeypatch.setattr(redis.Redis, 'ping', fake_ping)

    runpy.run_path(
        str(Path(app_module.__file__).resolve()),
        run_name='audit_redis_logging',
    )

    captured = capsys.readouterr()
    assert 'configured Redis instance' in captured.out
    assert secret not in captured.out + captured.err
