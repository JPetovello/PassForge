from types import SimpleNamespace

import pytest
import app as app_module


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(app_module.limiter, 'enabled', False)
    with app_module.app.test_client() as test_client:
        yield test_client


def test_prefix_only_endpoint_returns_padded_range(client, monkeypatch):
    prefix = 'ABCDE'
    body = f'{"F" * 35}:7\r\n{"0" * 35}:0\r\n'

    def fake_get(url, *, headers, timeout):
        assert url == f'https://api.pwnedpasswords.com/range/{prefix}'
        assert headers['Add-Padding'] == 'true'
        assert timeout == 5
        return SimpleNamespace(status_code=200, text=body)

    monkeypatch.setattr(app_module.requests, 'get', fake_get)
    response = client.get(f'/api/hibp/{prefix}')
    assert response.status_code == 200
    assert response.get_data(as_text=True) == body
    assert response.mimetype == 'text/plain'
    assert response.headers['Cache-Control'] == 'no-store'


@pytest.mark.parametrize('prefix', ['ABCD', 'ABCDE0', 'ZZZZZ'])
def test_prefix_only_endpoint_rejects_invalid_prefix(client, monkeypatch, prefix):
    def unexpected_request(*args, **kwargs):
        raise AssertionError('Invalid prefixes must not reach HIBP')

    monkeypatch.setattr(app_module.requests, 'get', unexpected_request)
    response = client.get(f'/api/hibp/{prefix}')
    assert response.status_code == 400


def test_prefix_only_endpoint_reports_hibp_failure(client, monkeypatch):
    monkeypatch.setattr(
        app_module.requests,
        'get',
        lambda *args, **kwargs: SimpleNamespace(status_code=503, text=''),
    )
    response = client.get('/api/hibp/ABCDE')
    assert response.status_code == 503
    assert response.get_json()['error'] == 'HIBP check unavailable'
