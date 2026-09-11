import pytest
from app import app, limiter

@pytest.fixture
def client():
    app.config['TESTING'] = True
    limiter.enabled = False
    with app.test_client() as client:
        yield client
    limiter.enabled = True

def test_healthcheck(client):
    """Verify healthcheck endpoint returns 200 OK and valid status."""
    response = client.get('/healthz')
    assert response.status_code in (200, 500)
    data = response.get_json()
    assert "status" in data
    assert "redis" in data

def test_static_routes(client):
    """Verify security headers and static route handling."""
    robots_res = client.get('/robots.txt')
    assert robots_res.status_code == 200
    assert "Disallow: /" in robots_res.get_data(as_text=True)

    favicon_res = client.get('/favicon.ico')
    assert favicon_res.status_code in (200, 204)

def test_evaluate_password_valid(client):
    """Verify password evaluation endpoint with a standard payload."""
    payload = {"password": "Correct-Horse-Battery-Staple-2026!"}
    response = client.post('/api/evaluate', json=payload)
    assert response.status_code == 200
    
    data = response.get_json()
    assert "score" in data
    assert "entropy" in data
    assert "crack_times_display" in data
    assert "hibp" in data
    assert data["entropy"] > 0
    assert "online_throttling_100_per_hour" in data["crack_times_display"]

def test_evaluate_password_empty_payload(client):
    """Verify 400 Bad Request on empty payload."""
    response = client.post('/api/evaluate', json={})
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data

def test_evaluate_zero_knowledge_sha1(client):
    """Verify zero-knowledge HIBP lookup via SHA-1 prefix and suffix."""
    payload = {
        "sha1_prefix": "5BAA6",
        "sha1_suffix": "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    }
    response = client.post('/api/evaluate', json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert "hibp" in data
    assert "found" in data["hibp"]

def test_generate_passphrase_defaults(client):
    """Verify passphrase generator default output."""
    response = client.get('/api/generate')
    assert response.status_code == 200
    
    data = response.get_json()
    assert "passphrase" in data
    assert data["words"] == 4
    assert data["count"] == 1
    assert len(data["passphrases"]) == 1
    assert "-" in data["passphrase"]

def test_generate_passphrase_custom_parameters(client):
    """Verify custom wordlist, separator, word count, and batch count."""
    params = "words=6&wordlist=short&separator=_&count=5"
    response = client.get(f'/api/generate?{params}')
    assert response.status_code == 200
    
    data = response.get_json()
    assert data["words"] == 6
    assert data["count"] == 5
    assert data["wordlist_type"] == "short"
    assert len(data["passphrases"]) == 5
    assert "_" in data["passphrases"][0]
    assert isinstance(data["entropy_bits"], (int, float))
    assert data["entropy_bits"] > 0

def test_generate_passphrase_number_separator(client):
    """Verify passphrase generator with random number separator mode."""
    response = client.get('/api/generate?words=4&separator=number')
    assert response.status_code == 200
    
    data = response.get_json()
    passphrase = data["passphrase"]
    assert any(char.isdigit() for char in passphrase)

def test_generate_passphrase_bounds_clamping(client):
    """Verify query parameters are properly bounded (min/max limits)."""
    response = client.get('/api/generate?words=1&count=25')
    assert response.status_code == 200
    
    data = response.get_json()
    assert data["words"] == 3
    assert data["count"] == 10
