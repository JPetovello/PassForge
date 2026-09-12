from types import SimpleNamespace

import pytest
import app as app_module


@pytest.mark.parametrize('count', [0, 7])
def test_hibp_requests_padding_and_handles_counts(monkeypatch, count):
    prefix = 'ABCDE'
    suffix = 'F' * 35
    calls = []

    def fake_get(url, *, headers, timeout):
        calls.append(url)
        assert url == f'https://api.pwnedpasswords.com/range/{prefix}'
        assert headers['Add-Padding'] == 'true'
        assert headers['User-Agent'] == 'PassForge-Homelab-App'
        assert timeout == 5
        return SimpleNamespace(
            status_code=200,
            text=f'{"0" * 35}:0\r\n{suffix}:{count}\r\n',
        )

    monkeypatch.setattr(app_module.requests, 'get', fake_get)
    monkeypatch.setattr(app_module.limiter, 'enabled', False)
    with app_module.app.test_client() as client:
        response = client.post('/api/evaluate', json={
            'sha1_prefix': prefix, 'sha1_suffix': suffix,
        })
    assert response.status_code == 200
    assert len(calls) == 1
    assert response.get_json()['hibp'] == {
        'available': True, 'found': count > 0, 'count': count,
    }
