import re

import pytest

import app as app_module


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(app_module.limiter, "enabled", False)
    with app_module.app.test_client() as test_client:
        yield test_client


def parse_csp(response):
    directives = {}
    for directive in response.headers["Content-Security-Policy"].split(";"):
        parts = directive.strip().split()
        if parts:
            directives[parts[0]] = parts[1:]
    return directives


def response_nonce(response):
    script_sources = parse_csp(response)["script-src"]
    nonce_sources = [
        source for source in script_sources if source.startswith("'nonce-")
    ]
    assert len(nonce_sources) == 1
    return nonce_sources[0][len("'nonce-"):-1]


def test_csp_has_restrictive_explicit_directives(client):
    response = client.get("/")
    directives = parse_csp(response)

    assert directives["default-src"] == ["'self'"]
    assert directives["base-uri"] == ["'none'"]
    assert directives["connect-src"] == ["'self'"]
    assert directives["form-action"] == ["'self'"]
    assert directives["frame-ancestors"] == ["'none'"]
    assert directives["object-src"] == ["'none'"]
    assert directives["script-src-attr"] == ["'none'"]
    assert directives["worker-src"] == ["'self'"]


def test_csp_allows_no_external_origins(client):
    policy = client.get("/").headers["Content-Security-Policy"]

    assert "http:" not in policy
    assert "https:" not in policy
    assert "data:" not in policy
    assert "blob:" not in policy
    assert "*" not in policy


def test_script_policy_uses_nonce_without_unsafe_inline(client):
    response = client.get("/")
    script_sources = parse_csp(response)["script-src"]

    assert "'self'" in script_sources
    assert "'unsafe-inline'" not in script_sources
    assert re.fullmatch(r"[A-Za-z0-9_-]{22}", response_nonce(response))


def test_style_policy_preserves_only_required_inline_compatibility(client):
    response = client.get("/")
    directives = parse_csp(response)
    nonce_source = f"'nonce-{response_nonce(response)}'"

    assert directives["style-src"] == ["'self'", "'unsafe-inline'"]
    assert directives["style-src-attr"] == ["'unsafe-inline'"]
    assert directives["style-src-elem"] == ["'self'", nonce_source]


def test_inline_script_and_style_elements_have_matching_nonce(client):
    response = client.get("/")
    html = response.get_data(as_text=True)
    nonce = response_nonce(response)

    inline_scripts = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", html)
    inline_styles = re.findall(r"<style[^>]*>", html)

    assert len(inline_scripts) == 3
    assert len(inline_styles) == 1
    assert all(f'nonce="{nonce}"' in tag for tag in inline_scripts)
    assert all(f'nonce="{nonce}"' in tag for tag in inline_styles)


def test_csp_nonce_is_unique_per_response(client):
    assert response_nonce(client.get("/")) != response_nonce(client.get("/"))


def test_existing_security_headers_remain_intact(client):
    response = client.get("/")

    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == (
        "strict-origin-when-cross-origin"
    )
