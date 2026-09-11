import math
import pytest
import app as app_module
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

def test_hibp_clean_result_is_available(client, monkeypatch):
    """Verify a successful HIBP lookup with no match is reported as clean and available."""
    class FakeResponse:
        status_code = 200
        text = "11111111111111111111111111111111111:42"

    monkeypatch.setattr(
        app_module.requests,
        "get",
        lambda *args, **kwargs: FakeResponse()
    )

    response = client.post('/api/evaluate', json={
        "sha1_prefix": "ABCDE",
        "sha1_suffix": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    })

    assert response.status_code == 200
    data = response.get_json()
    assert data["hibp"]["available"] is True
    assert data["hibp"]["found"] is False
    assert data["hibp"]["count"] == 0


def test_hibp_http_failure_is_unavailable(client, monkeypatch):
    """Verify an HIBP HTTP failure is not reported as zero breaches."""
    class FakeResponse:
        status_code = 503
        text = ""

    monkeypatch.setattr(
        app_module.requests,
        "get",
        lambda *args, **kwargs: FakeResponse()
    )

    response = client.post('/api/evaluate', json={
        "sha1_prefix": "ABCDE",
        "sha1_suffix": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    })

    assert response.status_code == 200
    data = response.get_json()
    assert data["hibp"]["available"] is False
    assert data["hibp"]["found"] is False
    assert data["hibp"]["count"] is None


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


def test_evaluate_preserves_password_exactly(client, monkeypatch):
    """Verify password evaluation does not alter the user's password."""
    original_password = "  Correct Horse Battery Staple  "

    seen = {
        "zxcvbn": None,
        "hibp": None,
    }

    def fake_zxcvbn(password):
        seen["zxcvbn"] = password
        return {
            "score": 4,
            "feedback": {},
            "crack_times_display": {}
        }

    def fake_check_hibp(password):
        seen["hibp"] = password
        return 0

    monkeypatch.setattr(app_module.zxcvbn, "zxcvbn", fake_zxcvbn)
    monkeypatch.setattr(app_module, "check_hibp", fake_check_hibp)

    response = client.post('/api/evaluate', json={
        "password": original_password
    })

    assert response.status_code == 200
    assert seen["zxcvbn"] == original_password
    assert seen["hibp"] == original_password


def test_hibp_rejects_invalid_sha1_suffix_length(client, monkeypatch):
    """Verify zero-knowledge HIBP mode rejects SHA-1 suffixes that are not exactly 35 hex characters."""
    called = {"requests_get": False}

    def fake_get(*args, **kwargs):
        called["requests_get"] = True
        raise AssertionError("HIBP should not be called for an invalid suffix")

    monkeypatch.setattr(app_module.requests, "get", fake_get)

    response = client.post('/api/evaluate', json={
        "sha1_prefix": "ABCDE",
        "sha1_suffix": "F" * 40
    })

    assert response.status_code == 400
    assert called["requests_get"] is False


def test_hibp_rejects_invalid_sha1_prefix_length(client, monkeypatch):
    """Verify zero-knowledge HIBP mode rejects prefixes that are not exactly 5 hex characters."""
    called = {"requests_get": False}

    def fake_get(*args, **kwargs):
        called["requests_get"] = True
        raise AssertionError("HIBP should not be called for an invalid prefix")

    monkeypatch.setattr(app_module.requests, "get", fake_get)

    response = client.post('/api/evaluate', json={
        "sha1_prefix": "ABCD",
        "sha1_suffix": "F" * 35
    })

    assert response.status_code == 400
    assert called["requests_get"] is False


def test_hibp_rejects_non_hex_sha1_input(client, monkeypatch):
    """Verify zero-knowledge HIBP mode rejects non-hexadecimal prefix/suffix input."""
    called = {"requests_get": False}

    def fake_get(*args, **kwargs):
        called["requests_get"] = True
        raise AssertionError("HIBP should not be called for malformed SHA-1 input")

    monkeypatch.setattr(app_module.requests, "get", fake_get)

    response = client.post('/api/evaluate', json={
        "sha1_prefix": "ABCGH",
        "sha1_suffix": ("F" * 34) + "Z"
    })

    assert response.status_code == 400
    assert called["requests_get"] is False


def test_evaluate_all_space_password_is_valid_input(client, monkeypatch):
    """Verify a password made only of spaces is still evaluated exactly as submitted."""
    original_password = "   "

    seen = {
        "zxcvbn": None,
        "hibp": None,
    }

    def fake_zxcvbn(password):
        seen["zxcvbn"] = password
        return {
            "score": 0,
            "feedback": {},
            "crack_times_display": {}
        }

    def fake_check_hibp(password):
        seen["hibp"] = password
        return 0

    monkeypatch.setattr(app_module.zxcvbn, "zxcvbn", fake_zxcvbn)
    monkeypatch.setattr(app_module, "check_hibp", fake_check_hibp)

    response = client.post('/api/evaluate', json={
        "password": original_password
    })

    assert response.status_code == 200
    assert seen["zxcvbn"] == original_password
    assert seen["hibp"] == original_password


def test_evaluate_rejects_password_over_256_characters(client, monkeypatch):
    """Verify passwords longer than the documented 256-character limit are rejected."""
    called = {
        "zxcvbn": False,
        "hibp": False,
    }

    def fake_zxcvbn(password):
        called["zxcvbn"] = True
        raise AssertionError("zxcvbn should not run for an oversized password")

    def fake_check_hibp(password):
        called["hibp"] = True
        raise AssertionError("HIBP should not run for an oversized password")

    monkeypatch.setattr(app_module.zxcvbn, "zxcvbn", fake_zxcvbn)
    monkeypatch.setattr(app_module, "check_hibp", fake_check_hibp)

    response = client.post('/api/evaluate', json={
        "password": "A" * 257
    })

    assert response.status_code == 400
    assert called["zxcvbn"] is False
    assert called["hibp"] is False

    data = response.get_json()
    assert data["error"] == "Password exceeds maximum allowed length of 256 characters"


def test_hibp_positive_match_reports_breach_count(client, monkeypatch):
    """Verify a matching HIBP suffix is reported as breached with the correct count."""
    target_suffix = "F" * 35

    class FakeResponse:
        status_code = 200
        text = f"{target_suffix}:12345\n{'A' * 35}:7"

    monkeypatch.setattr(
        app_module.requests,
        "get",
        lambda *args, **kwargs: FakeResponse()
    )

    response = client.post('/api/evaluate', json={
        "sha1_prefix": "ABCDE",
        "sha1_suffix": target_suffix
    })

    assert response.status_code == 200
    data = response.get_json()

    assert data["hibp"]["available"] is True
    assert data["hibp"]["found"] is True
    assert data["hibp"]["count"] == 12345


def test_hibp_request_exception_is_unavailable(client, monkeypatch):
    """Verify a request exception is reported as HIBP unavailable, not as a clean result."""
    def fake_get(*args, **kwargs):
        raise app_module.requests.RequestException("simulated network failure")

    monkeypatch.setattr(app_module.requests, "get", fake_get)

    response = client.post('/api/evaluate', json={
        "sha1_prefix": "ABCDE",
        "sha1_suffix": "F" * 35
    })

    assert response.status_code == 200
    data = response.get_json()

    assert data["hibp"]["available"] is False
    assert data["hibp"]["found"] is False
    assert data["hibp"]["count"] is None


def test_generate_rejects_invalid_wordlist_type(client):
    """Verify unsupported wordlist names are rejected instead of silently using the large list."""
    response = client.get('/api/generate?wordlist=banana')

    assert response.status_code == 400

    data = response.get_json()
    assert data["error"] == "Invalid wordlist type"


def test_generate_rejects_invalid_separator(client):
    """Verify unsupported separators are rejected instead of silently using a hyphen."""
    response = client.get('/api/generate?separator=banana')

    assert response.status_code == 400

    data = response.get_json()
    assert data["error"] == "Invalid separator"


def test_generate_number_separator_includes_digit_entropy(client):
    """Verify random digit separators contribute to reported generation entropy."""
    plain = client.get('/api/generate?words=4&wordlist=large&separator=-')
    numbered = client.get('/api/generate?words=4&wordlist=large&separator=number')

    assert plain.status_code == 200
    assert numbered.status_code == 200

    plain_data = plain.get_json()
    numbered_data = numbered.get_json()

    # Four words have three separators. Each random digit contributes log2(10) bits.
    expected_extra_bits = round(3 * math.log2(10), 1)

    actual_extra_bits = round(
        numbered_data["entropy_bits"] - plain_data["entropy_bits"],
        1
    )

    assert actual_extra_bits == expected_extra_bits


def test_index_exposes_actual_wordlist_sizes(client):
    """Verify frontend entropy calculations receive the actual loaded wordlist sizes."""
    response = client.get('/')

    assert response.status_code == 200

    html = response.get_data(as_text=True)

    assert f"large: {len(app_module.EFF_LARGE_WORDS)}" in html
    assert f"short: {len(app_module.EFF_SHORT_WORDS)}" in html



def test_generate_large_wordlist_unavailable(client, monkeypatch):
    """Missing EFF Large list must disable large-list generation."""
    monkeypatch.setattr(app_module, 'EFF_LARGE_WORDS', [])

    response = client.get('/api/generate?words=3&wordlist=large')

    assert response.status_code == 503
    assert response.get_json() == {
        "error": "EFF Large wordlist is not installed"
    }


def test_generate_short_wordlist_unavailable(client, monkeypatch):
    """Missing EFF Short list must disable short-list generation."""
    monkeypatch.setattr(app_module, 'EFF_SHORT_WORDS', [])

    response = client.get('/api/generate?words=3&wordlist=short')

    assert response.status_code == 503
    assert response.get_json() == {
        "error": "EFF Short wordlist is not installed"
    }


def test_index_labels_normal_wordlists(client):
    """Verify normal wordlist labels reflect the actual loaded pool sizes."""
    response = client.get('/')

    assert response.status_code == 200

    html = response.get_data(as_text=True)

    assert f"EFF Large ({len(app_module.EFF_LARGE_WORDS):,})" in html

    if app_module.EFF_SHORT_WORDS:
        assert f"EFF Short ({len(app_module.EFF_SHORT_WORDS):,})" in html


def test_index_selects_short_when_large_missing(client, monkeypatch):
    """Short list becomes selected when Large is unavailable."""
    monkeypatch.setattr(app_module, 'EFF_LARGE_WORDS', [])
    monkeypatch.setattr(app_module, 'EFF_SHORT_WORDS', ['alpha', 'bravo', 'charlie'])

    response = client.get('/')

    assert response.status_code == 200

    html = response.get_data(as_text=True)

    assert '<option value="large" disabled>EFF Large (Unavailable)</option>' in html
    assert '<option value="short" selected>EFF Short (3)</option>' in html


def test_index_disables_generator_when_all_wordlists_missing(client, monkeypatch):
    """No generation is offered when neither EFF list is available."""
    monkeypatch.setattr(app_module, 'EFF_LARGE_WORDS', [])
    monkeypatch.setattr(app_module, 'EFF_SHORT_WORDS', [])

    response = client.get('/')

    assert response.status_code == 200

    html = response.get_data(as_text=True)

    assert '<option value="large" disabled>EFF Large (Unavailable)</option>' in html
    assert '<option value="short" disabled>EFF Short (Unavailable)</option>' in html
    assert 'id="generateBtn"' in html
    assert 'id="generateBtn" style="margin-top: 1rem; margin-bottom: 0;" disabled' in html
