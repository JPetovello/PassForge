import pytest
import app as app_module


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(app_module.limiter, 'enabled', False)
    with app_module.app.test_client() as test_client:
        yield test_client


@pytest.mark.parametrize('list_type,expected_size', [
    ('large', app_module.EFF_LARGE_LINES),
    ('short', app_module.EFF_SHORT_LINES),
])
def test_verified_wordlist_is_served(client, list_type, expected_size):
    response = client.get(f'/wordlists/{list_type}.txt')
    assert response.status_code == 200
    assert response.mimetype == 'text/plain'
    assert response.headers['Cache-Control'] == 'public, max-age=86400'
    words = response.get_data(as_text=True).splitlines()
    assert len(words) == expected_size
    assert all(word and not any(char.isspace() for char in word) for word in words)


def test_invalid_wordlist_is_not_served(client):
    response = client.get('/wordlists/unknown.txt')
    assert response.status_code == 404
    assert response.get_json()['error'] == 'Invalid wordlist type'


def test_unverified_wordlist_is_not_served(client, monkeypatch):
    monkeypatch.setattr(app_module, 'EFF_LARGE_WORDS', [])
    response = client.get('/wordlists/large.txt')
    assert response.status_code == 503
    assert response.get_json()['error'] == 'EFF Large wordlist is unavailable'
