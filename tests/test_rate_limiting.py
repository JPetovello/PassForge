import re
import runpy
from pathlib import Path

import pytest
import redis

import app as app_module


@pytest.fixture(autouse=True)
def reset_limiter(monkeypatch):
    original_enabled = app_module.limiter.enabled
    monkeypatch.setattr(app_module, "TRUSTED_PROXY_HOPS", 0)
    app_module.limiter.enabled = True
    app_module.limiter.reset()
    yield
    app_module.limiter.reset()
    app_module.limiter.enabled = original_enabled


def client_address(*, remote_addr="192.0.2.10", headers=None):
    with app_module.app.test_request_context(
        "/",
        environ_base={"REMOTE_ADDR": remote_addr},
        headers=headers,
    ):
        return app_module.get_rate_limit_client_address()


def test_direct_peer_is_default_client_identity():
    assert client_address(remote_addr="192.0.2.10") == "192.0.2.10"


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Forwarded-For": "198.51.100.20"},
        {"X-Real-IP": "198.51.100.20"},
        {"Forwarded": "for=198.51.100.20"},
    ],
)
def test_forwarding_headers_are_ignored_by_default(headers):
    assert client_address(headers=headers) == "192.0.2.10"


def test_explicit_proxy_hops_select_right_hand_trust_boundary(monkeypatch):
    monkeypatch.setattr(app_module, "TRUSTED_PROXY_HOPS", 2)

    assert client_address(
        remote_addr="192.0.2.200",
        headers={
            "X-Forwarded-For": (
                "203.0.113.250, 198.51.100.25, 192.0.2.100"
            )
        },
    ) == "198.51.100.25"


def test_trusted_mode_still_ignores_other_forwarding_headers(monkeypatch):
    monkeypatch.setattr(app_module, "TRUSTED_PROXY_HOPS", 1)

    assert client_address(
        remote_addr="192.0.2.10",
        headers={
            "Forwarded": "for=198.51.100.20",
            "X-Real-IP": "198.51.100.21",
        },
    ) == "192.0.2.10"


def test_extra_left_hand_forwarded_entries_cannot_change_boundary(monkeypatch):
    monkeypatch.setattr(app_module, "TRUSTED_PROXY_HOPS", 2)

    base_headers = {"X-Forwarded-For": "198.51.100.25, 192.0.2.100"}
    injected_headers = {
        "X-Forwarded-For": (
            "203.0.113.7, 203.0.113.8, 198.51.100.25, 192.0.2.100"
        )
    }

    assert client_address(headers=base_headers) == "198.51.100.25"
    assert client_address(headers=injected_headers) == "198.51.100.25"


@pytest.mark.parametrize(
    "forwarded_for",
    [
        "",
        "198.51.100.25",
        "198.51.100.25, not-an-ip",
        "198.51.100.25, ",
    ],
)
def test_unsafe_forwarded_chain_falls_back_to_direct_peer(
    monkeypatch, forwarded_for
):
    monkeypatch.setattr(app_module, "TRUSTED_PROXY_HOPS", 2)

    assert client_address(
        remote_addr="192.0.2.10",
        headers={"X-Forwarded-For": forwarded_for},
    ) == "192.0.2.10"


def test_trusted_proxy_supports_ipv4_and_ipv6(monkeypatch):
    monkeypatch.setattr(app_module, "TRUSTED_PROXY_HOPS", 1)

    assert client_address(
        headers={"X-Forwarded-For": "198.51.100.25"}
    ) == "198.51.100.25"
    assert client_address(
        headers={"X-Forwarded-For": "2001:db8::25"}
    ) == "2001:db8::25"


@pytest.mark.parametrize("value", ["", "one", "-1", "11", "1.5"])
def test_invalid_proxy_hop_configuration_fails_safely(monkeypatch, value):
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", value)

    with pytest.raises(ValueError, match="integer from 0 through 10"):
        app_module.resolve_trusted_proxy_hops()


@pytest.mark.parametrize("value, expected", [("0", 0), ("1", 1), ("10", 10)])
def test_valid_proxy_hop_configuration(monkeypatch, value, expected):
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", value)

    assert app_module.resolve_trusted_proxy_hops() == expected


def test_spoofed_x_forwarded_for_cannot_bypass_direct_rate_limit(monkeypatch):
    monkeypatch.setattr(app_module, "fetch_hibp_range", lambda prefix: "")

    with app_module.app.test_client() as client:
        for request_number in range(15):
            response = client.post(
                "/api/hibp",
                json={"prefix": "ABCDE"},
                headers={"X-Forwarded-For": f"198.51.100.{request_number + 1}"},
                environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
            )
            assert response.status_code == 200

        response = client.post(
            "/api/hibp",
            json={"prefix": "ABCDE"},
            headers={"X-Forwarded-For": "203.0.113.250"},
            environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
        )

    assert response.status_code == 429
    assert response.get_json()["error"] == "Rate limit exceeded"


def test_default_rate_limit_429_retains_nonce_csp():
    client_address = {"REMOTE_ADDR": "192.0.2.55"}

    with app_module.app.test_client() as client:
        for _ in range(50):
            response = client.get(
                "/",
                environ_overrides=client_address,
            )
            assert response.status_code == 200

        limited = client.get(
            "/",
            environ_overrides=client_address,
        )

    assert limited.status_code == 429
    assert limited.get_json()["error"] == "Rate limit exceeded"

    policy = limited.headers["Content-Security-Policy"]
    nonce_match = re.search(
        r"script-src 'self' 'nonce-([A-Za-z0-9_-]{22})'",
        policy,
    )

    assert nonce_match is not None
    nonce = nonce_match.group(1)
    assert f"style-src-elem 'self' 'nonce-{nonce}'" in policy


def test_explicit_proxy_clients_receive_independent_rate_limit_buckets(monkeypatch):
    monkeypatch.setattr(app_module, "TRUSTED_PROXY_HOPS", 1)
    monkeypatch.setattr(app_module, "fetch_hibp_range", lambda prefix: "")
    proxy_address = {"REMOTE_ADDR": "192.0.2.200"}

    with app_module.app.test_client() as client:
        for _ in range(15):
            response = client.post(
                "/api/hibp",
                json={"prefix": "ABCDE"},
                headers={"X-Forwarded-For": "198.51.100.10"},
                environ_overrides=proxy_address,
            )
            assert response.status_code == 200

        limited = client.post(
            "/api/hibp",
            json={"prefix": "ABCDE"},
            headers={"X-Forwarded-For": "198.51.100.10"},
            environ_overrides=proxy_address,
        )
        independent = client.post(
            "/api/hibp",
            json={"prefix": "ABCDE"},
            headers={"X-Forwarded-For": "198.51.100.11"},
            environ_overrides=proxy_address,
        )

    assert limited.status_code == 429
    assert independent.status_code == 200


def test_no_redis_configuration_uses_memory_storage():
    assert app_module.REDIS_URL == "memory://"
    assert app_module.limiter._storage_uri == "memory://"


def test_redis_configuration_selects_limiter_storage(monkeypatch):
    redis_url = "redis://:test-secret@192.0.2.50:6379/4"
    monkeypatch.setenv("REDIS_URL", redis_url)
    monkeypatch.setattr(redis.Redis, "ping", lambda self: True)

    loaded = runpy.run_path(
        str(Path(app_module.__file__).resolve()),
        run_name="test_redis_limiter_storage",
    )

    assert loaded["REDIS_URL"] == redis_url
    assert loaded["limiter"]._storage_uri == redis_url
