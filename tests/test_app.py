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

    sw_res = client.get('/sw.js')
    assert sw_res.status_code == 200
    assert sw_res.mimetype == 'application/javascript'
    assert "passforge-v3" in sw_res.get_data(as_text=True)



































def test_index_exposes_actual_wordlist_sizes(client):
    """Verify frontend entropy calculations receive the actual loaded wordlist sizes."""
    response = client.get('/')

    assert response.status_code == 200

    html = response.get_data(as_text=True)

    assert f"large: {len(app_module.EFF_LARGE_WORDS)}" in html
    assert f"short: {len(app_module.EFF_SHORT_WORDS)}" in html







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

def test_load_wordlist_accepts_verified_file(tmp_path, monkeypatch):
    """A wordlist loads when its SHA-256 and entry count match."""
    content = b"11111\talpha\n22222\tbravo\n"
    wordlist = tmp_path / "test_wordlist.txt"
    wordlist.write_bytes(content)

    monkeypatch.setattr(app_module, "__file__", str(tmp_path / "app.py"))

    expected_hash = app_module.hashlib.sha256(content).hexdigest()

    words = app_module.load_wordlist(
        "test_wordlist.txt",
        expected_hash,
        2,
    )

    assert words == ["alpha", "bravo"]


def test_load_wordlist_rejects_bad_sha256(tmp_path, monkeypatch):
    """A wordlist whose contents do not match the pinned hash must be rejected."""
    content = b"11111\talpha\n22222\tbravo\n"
    wordlist = tmp_path / "test_wordlist.txt"
    wordlist.write_bytes(content)

    monkeypatch.setattr(app_module, "__file__", str(tmp_path / "app.py"))

    words = app_module.load_wordlist(
        "test_wordlist.txt",
        "0" * 64,
        2,
    )

    assert words == []


def test_load_wordlist_rejects_wrong_line_count(tmp_path, monkeypatch):
    """A correctly hashed file with an unexpected entry count must be rejected."""
    content = b"11111\talpha\n22222\tbravo\n"
    wordlist = tmp_path / "test_wordlist.txt"
    wordlist.write_bytes(content)

    monkeypatch.setattr(app_module, "__file__", str(tmp_path / "app.py"))

    expected_hash = app_module.hashlib.sha256(content).hexdigest()

    words = app_module.load_wordlist(
        "test_wordlist.txt",
        expected_hash,
        3,
    )

    assert words == []

def test_entropy_target_labels_are_dynamic(client):
    """Entropy target word-count hints must be calculated from the active generator settings."""
    response = client.get('/')

    assert response.status_code == 200

    html = response.get_data(as_text=True)

    assert '<option value="60">60 bits</option>' in html
    assert '<option value="80">80 bits</option>' in html
    assert '<option value="100">100 bits</option>' in html
    assert '<option value="128">128 bits</option>' in html

    assert '60 bits (~5 words)' not in html
    assert '80 bits (~6 words)' not in html
    assert '100 bits (~8 words)' not in html
    assert '128 bits (~10 words)' not in html

    assert 'function requiredWordsForEntropy' in html
    assert 'function updateEntropyTargetLabels' in html

def test_footer_matches_passforge_branding(client):
    """Footer uses the PassForge copyright/license line without legacy version or AI text."""
    response = client.get('/')

    assert response.status_code == 200

    html = response.get_data(as_text=True)

    assert 'PassForge · © 2026 Jeff Petovello · Licensed under AGPLv3' in html
    assert 'Built with AI collaboration' not in html
    assert 'checked with local AI auditing' not in html
    assert 'PassForge latest' not in html


def test_resolve_redis_url_honors_database(monkeypatch):
    """Verify host/port Redis configuration honors REDIS_DB."""
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setenv("REDIS_HOST", "192.0.2.10")
    monkeypatch.setenv("REDIS_PORT", "6379")
    monkeypatch.setenv("REDIS_PASSWORD", "secret")
    monkeypatch.setenv("REDIS_DB", "3")

    assert (
        app_module.resolve_redis_url()
        == "redis://:secret@192.0.2.10:6379/3"
    )


def test_resolve_redis_url_explicit_url_takes_precedence(monkeypatch):
    """Verify REDIS_URL overrides host, port, password, and database settings."""
    monkeypatch.setenv("REDIS_URL", "redis://redis.example:6380/7")
    monkeypatch.setenv("REDIS_HOST", "192.0.2.10")
    monkeypatch.setenv("REDIS_PORT", "6379")
    monkeypatch.setenv("REDIS_PASSWORD", "secret")
    monkeypatch.setenv("REDIS_DB", "3")

    assert app_module.resolve_redis_url() == "redis://redis.example:6380/7"


def test_resolve_redis_url_falls_back_to_memory(monkeypatch):
    """Verify Redis remains optional when no host or URL is configured."""
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("REDIS_HOST", raising=False)

    assert app_module.resolve_redis_url() == "memory://"
