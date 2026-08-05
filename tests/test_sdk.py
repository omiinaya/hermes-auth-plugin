"""
Tests for the hermes-id App-Side SDK (offline-first verification).

Covers:
- ``verify_token_offline`` — pure, FastAPI-free local verification
  (signature + expiry + audience enforcement).
- ``load_server_card`` — fetch/verify/cache the auth server's identity card,
  with stale-cache fallback when the server is unreachable.
- ``RevocationChecker`` — best-effort online revocation (fail-open).
- ``HermesIDAuth`` — the FastAPI dependency: env contract, 401 paths,
  audience enforcement, offline-first behaviour.
- ``TokenCache`` — per-project persistent token cache.
"""

import base64
import contextlib
import json
import os
import threading
import time
from pathlib import Path

import httpx
import pytest

from hermes_id.auth_client import AuthClient
from hermes_id.identity import IdentityCard, create_identity
from hermes_id.sdk import (
    AuthError,
    RevocationChecker,
    TokenCache,
    default_card_cache_path,
    load_server_card,
    verify_token_offline,
)
from hermes_id.storage import IdentityStorage

_TEST_PASSWORD = "hermes-id-test-password-2026"  # same as test_server.py — identities decrypt under either module's env
_ADMIN_KEY = "sdk-test-admin-key"


def _start_uvicorn(app, host: str = "127.0.0.1"):
    """Start uvicorn on an ephemeral port; returns (base_url, stop_fn).

    Uses ``port=0`` so tests never collide on a fixed port, and a
    ``should_exit`` teardown so the socket is released cleanly when the
    module fixture tears down (no orphaned listeners between runs).
    """
    import uvicorn

    config = uvicorn.Config(app, host=host, port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("uvicorn failed to start")
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]

    def stop():
        server.should_exit = True
        thread.join(timeout=5)

    return f"http://{host}:{port}", stop


# ---------------------------------------------------------------------------
# Live auth server fixture (distinct port from test_server.py)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def server_identity(tmp_path_factory):
    identity_dir = tmp_path_factory.mktemp("sdk-server-identity")
    storage = IdentityStorage(directory=str(identity_dir))
    storage.create(_TEST_PASSWORD, metadata={"profile": "sdk-test-server"})
    return str(identity_dir)


@pytest.fixture(scope="module")
def client_identity(tmp_path_factory):
    identity_dir = tmp_path_factory.mktemp("sdk-client-identity")
    storage = IdentityStorage(directory=str(identity_dir))
    storage.create(_TEST_PASSWORD, metadata={"profile": "sdk-test-agent"})
    return str(identity_dir)


@pytest.fixture(scope="module")
def auth_server(server_identity, tmp_path_factory):
    """Start the auth server (ephemeral port) with a controlled passphrase.

    ``HERMES_ID_PASSPHRASE`` is set here (not at module import) so this
    module never clobbers the env var other test modules rely on; the
    previous value is restored at teardown.
    """
    _old_pass = os.environ.get("HERMES_ID_PASSPHRASE")
    os.environ["HERMES_ID_PASSPHRASE"] = _TEST_PASSWORD
    try:
        db_path = tmp_path_factory.mktemp("sdk-data") / "registry.db"
        from hermes_id.server import AuthServer

        server = AuthServer(
            identity_dir=server_identity,
            db_path=str(db_path),
            token_ttl=3600,
            challenge_ttl=60,
            admin_key=_ADMIN_KEY,
            cors_origins=["*"],
            # Module-scoped server accumulates /challenge calls across many
            # tests — a low rate_limit_max trips 429 spuriously. The limiter
            # is tested in test_server_edges, not here.
            rate_limit_max=5000,
        )

        base_url, stop = _start_uvicorn(server.app)
        yield {"url": base_url, "server": server}
        stop()

        if db_path.exists():
            db_path.unlink()
    finally:
        if _old_pass is None:
            os.environ.pop("HERMES_ID_PASSPHRASE", None)
        else:
            os.environ["HERMES_ID_PASSPHRASE"] = _old_pass


@pytest.fixture
def server_card(auth_server):
    """The live auth server's identity card dict."""
    return AuthClient(auth_server["url"]).get_identity()


@pytest.fixture
def agent_client(auth_server, client_identity):
    return AuthClient(auth_server["url"], identity_dir=client_identity)


@pytest.fixture
def admin_client(auth_server):
    return AuthClient(auth_server["url"], admin_key=_ADMIN_KEY)


@pytest.fixture
def server_url(auth_server):
    return auth_server["url"]


@pytest.fixture
def auth_cache_dir(tmp_path):
    """Per-test isolated card cache dir (prevents cross-run pollution of
    the real ~/.hermes/auth cache from different test identities)."""
    return tmp_path / "auth-cache"


@pytest.fixture(autouse=True)
def register_and_approve(agent_client, admin_client):
    """Ensure the test agent is registered and approved before each test."""
    card = agent_client._storage.get_identity_card()
    assert card is not None, "test agent identity missing"
    with contextlib.suppress(httpx.HTTPStatusError):
        agent_client.register_agent(card.id, display_name="SDK Test Agent")
    with contextlib.suppress(httpx.HTTPStatusError):
        admin_client.approve_agent(card.id)
    yield


@pytest.fixture
def token(agent_client):
    """A valid, approved, server-issued token."""
    card = agent_client._storage.get_identity_card()
    assert card is not None
    ch = agent_client.challenge(card.id)
    sig = agent_client.sign_challenge(ch["challenge_b64"])
    result = agent_client.authenticate(card.id, ch["challenge_b64"], sig, aud="spacetime-test")
    return result["token"]


# ---------------------------------------------------------------------------
# verify_token_offline — pure local verification
# ---------------------------------------------------------------------------

class TestVerifyTokenOffline:
    def test_valid_token(self, token, server_card):
        payload = verify_token_offline(token, server_card, project="spacetime-test")
        assert payload is not None
        assert payload["did"].startswith("did:hermes:")
        assert payload["aud"] == "spacetime-test"

    def test_accepts_identity_card_object(self, token, server_card):
        card_obj = IdentityCard.from_json(json.dumps(server_card))
        payload = verify_token_offline(token, card_obj, project="spacetime-test")
        assert payload is not None

    def test_wrong_audience_rejected(self, token, server_card):
        # The P2 security fix: token minted for spacetime-test must NOT
        # verify on a service scoped to another project.
        assert verify_token_offline(token, server_card, project="spacetime-other") is None

    def test_missing_audience_rejected_when_project_required(self, server_card, agent_client):
        card = agent_client._storage.get_identity_card()
        ch = agent_client.challenge(card.id)
        sig = agent_client.sign_challenge(ch["challenge_b64"])
        # Mint a token with NO audience
        result = agent_client.authenticate(card.id, ch["challenge_b64"], sig, aud=None)
        assert result.get("aud", "") == ""
        assert verify_token_offline(result["token"], server_card, project="spacetime-test") is None

    def test_expired_rejected(self, server_card, agent_client, monkeypatch):
        card = agent_client._storage.get_identity_card()
        ch = agent_client.challenge(card.id)
        sig = agent_client.sign_challenge(ch["challenge_b64"])
        token_str = agent_client.authenticate(card.id, ch["challenge_b64"], sig, aud="x")["token"]

        # Verify at a moment far in the future
        future = time.time() + 10_000
        assert verify_token_offline(token_str, server_card, project="x", now=future) is None

    def test_tampered_signature_rejected(self, token, server_card):
        payload_b64, sig_b64 = token.split(".")
        # Flip a character in the signature
        tampered_sig = ("A" if sig_b64[0] != "A" else "B") + sig_b64[1:]
        assert verify_token_offline(f"{payload_b64}.{tampered_sig}", server_card, project="spacetime-test") is None

    def test_tampered_payload_rejected(self, token, server_card):
        payload_b64, sig_b64 = token.split(".")
        bad_payload = ("A" if payload_b64[0] != "A" else "B") + payload_b64[1:]
        assert verify_token_offline(f"{bad_payload}.{sig_b64}", server_card, project="spacetime-test") is None

    def test_malformed_token_rejected(self, server_card):
        for bad in ("", "notatoken", "a.b.c", "!.!"):
            assert verify_token_offline(bad, server_card, project="spacetime-test") is None

    def test_wrong_card_rejected(self, token):
        # A token signed by the real server must fail against an unrelated card
        from hermes_id.crypto import generate_keypair

        private, public = generate_keypair()
        other_card = create_identity(private, public, metadata={"who": "impostor"})
        assert verify_token_offline(token, other_card.to_json(), project="spacetime-test") is None


# ---------------------------------------------------------------------------
# load_server_card — fetch / cache / stale fallback
# ---------------------------------------------------------------------------

class TestLoadServerCard:
    def test_fetches_and_verifies(self, server_url, server_card, tmp_path):
        card = load_server_card(server_url, cache_path=tmp_path / "card.json")
        assert card["id"] == server_card["id"]
        assert card["proof"]["type"] == "Ed25519Signature2020"

    def test_caches_to_disk(self, server_url, tmp_path):
        cache = tmp_path / "card.json"
        first = load_server_card(server_url, cache_path=cache)
        assert cache.exists()
        # Second call returns the same (cached) data without hitting network
        second = load_server_card(server_url, cache_path=cache, max_age=3600)
        assert first == second

    def test_stale_cache_fallback_when_server_down(self, server_url, tmp_path):
        cache = tmp_path / "card.json"
        real_card = load_server_card(server_url, cache_path=cache)
        assert real_card["id"].startswith("did:hermes:")

        # Make the cache STALE (older than max_age) so the loader tries network
        old = time.time() - 7200
        os.utime(cache, (old, old))

        # Point at a dead port with the stale cache
        dead_url = "http://127.0.0.1:1"
        with pytest.raises(AuthError):
            load_server_card(dead_url, cache_path=cache, allow_stale=False, max_age=3600, timeout=1.0)
        # With allow_stale=True, the stale cached card is used (offline-first)
        stale = load_server_card(dead_url, cache_path=cache, allow_stale=True, max_age=3600, timeout=1.0)
        assert stale["id"] == real_card["id"]

    def test_fresh_cache_short_circuits_network(self, server_url, tmp_path):
        """A fresh-enough cache is used without touching the network."""
        cache = tmp_path / "card.json"
        real_card = load_server_card(server_url, cache_path=cache)
        # Point at a dead port — fresh cache means no network needed
        card = load_server_card("http://127.0.0.1:1", cache_path=cache, allow_stale=False, timeout=1.0)
        assert card["id"] == real_card["id"]

    def test_no_cache_no_server_raises(self, tmp_path):
        cache = tmp_path / "missing.json"
        with pytest.raises(AuthError):
            load_server_card("http://127.0.0.1:1", cache_path=cache, allow_stale=False, timeout=1.0)

    def test_default_cache_path_is_deterministic(self):
        p1 = default_card_cache_path("http://192.168.1.10:9488")
        p2 = default_card_cache_path("http://192.168.1.10:9488")
        assert p1 == p2
        assert "server-card-" in str(p1)


# ---------------------------------------------------------------------------
# RevocationChecker — best-effort online revocation (fail-open)
# ---------------------------------------------------------------------------

class TestRevocationChecker:
    @staticmethod
    def _token_payload(token: str) -> dict:
        return json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "==").decode())

    def test_valid_token_not_revoked(self, token, server_url):
        checker = RevocationChecker(server_url)
        payload = self._token_payload(token)
        assert checker.is_revoked(token, payload["token_id"]) is False

    def test_revoked_token_detected(self, agent_client, auth_server):
        server_url = auth_server["url"]
        card = agent_client._storage.get_identity_card()
        assert card is not None
        ch = agent_client.challenge(card.id)
        sig = agent_client.sign_challenge(ch["challenge_b64"])
        result = agent_client.authenticate(card.id, ch["challenge_b64"], sig, aud="x")
        token_str = result["token"]
        token_id = result["token_id"]

        checker = RevocationChecker(server_url)
        assert checker.is_revoked(token_str, token_id) is False

        agent_client.revoke_token(token_str)
        # A FRESH checker (no cached answer) now sees the token as revoked
        fresh = RevocationChecker(server_url)
        assert fresh.is_revoked(token_str, token_id) is True

    def test_revocation_answer_cached(self, token, server_url):
        """Within TTL, repeated checks reuse the cached answer (no server hit)."""
        payload = self._token_payload(token)
        checker = RevocationChecker(server_url)
        assert checker.is_revoked(token, payload["token_id"]) is False
        # Second call within TTL returns cached False — no exception, same answer
        assert checker.is_revoked(token, payload["token_id"]) is False

    def test_fail_open_when_server_down(self, token):
        checker = RevocationChecker("http://127.0.0.1:1", timeout=1.0)
        payload = self._token_payload(token)
        # Offline checks passed ⇒ server unreachable must NOT revoke
        assert checker.is_revoked(token, payload["token_id"]) is False

    def test_no_token_id_not_revoked(self, token, server_url):
        checker = RevocationChecker(server_url)
        assert checker.is_revoked(token, "") is False

    def test_verify_env_false_honored(self, monkeypatch):
        """A standalone RevocationChecker honors HERMES_AUTH_VERIFY=false,
        matching AuthClient / HermesIDAuth behavior."""
        monkeypatch.setenv("HERMES_AUTH_VERIFY", "false")
        checker = RevocationChecker("http://auth.test")
        assert checker._verify is False

    def test_verify_env_true_honored(self, monkeypatch):
        """HERMES_AUTH_VERIFY=true resolves to True."""
        monkeypatch.setenv("HERMES_AUTH_VERIFY", "true")
        checker = RevocationChecker("http://auth.test")
        assert checker._verify is True

    def test_verify_env_ca_path_honored(self, monkeypatch):
        """HERMES_AUTH_VERIFY as a CA-bundle path is passed through."""
        monkeypatch.setenv("HERMES_AUTH_VERIFY", "/tmp/ca.pem")
        checker = RevocationChecker("http://auth.test")
        assert checker._verify == "/tmp/ca.pem"

    def test_verify_explicit_false_wins_over_env(self, monkeypatch):
        """An explicit verify=False beats the env var."""
        monkeypatch.setenv("HERMES_AUTH_VERIFY", "true")
        checker = RevocationChecker("http://auth.test", verify=False)
        assert checker._verify is False

    def test_expired_entries_swept(self, token, server_url):
        """Cache entries past their TTL are evicted so a stream of unique
        token_ids can't grow the dict without limit."""
        checker = RevocationChecker(server_url)
        payload = self._token_payload(token)
        checker.is_revoked(token, payload["token_id"])
        assert len(checker._cache) == 1
        # Age the entry past TTL, then sweep directly — must disappear.
        old = time.time() - checker._ttl - 10.0
        checker._cache[payload["token_id"]] = (False, old)
        checker._sweep(time.time())
        assert len(checker._cache) == 0

    def test_sweep_preserves_fresh_entries(self, token, server_url):
        """Fresh cache entries survive the sweep."""
        checker = RevocationChecker(server_url)
        payload = self._token_payload(token)
        checker.is_revoked(token, payload["token_id"])
        checker._sweep(time.time())
        assert len(checker._cache) == 1

    def test_sweep_triggered_every_64_lookups(self):
        """The sweep runs opportunistically on cache writes (misses)."""
        # Unreachable server → every miss fails open fast and writes cache.
        checker = RevocationChecker("http://127.0.0.1:1", timeout=0.5)
        checker._sweeps = 63
        checker.is_revoked("x.y", "tid-0")  # 64th call → sweep runs
        assert checker._sweeps == 64


# ---------------------------------------------------------------------------
# HermesIDAuth — FastAPI dependency
# ---------------------------------------------------------------------------

class TestHermesIDAuth:
    def _make_auth(self, server_url, project, cache_dir, **kw):
        from hermes_id.fastapi_middleware import HermesIDAuth

        return HermesIDAuth(server_url=server_url, project=project, cache_dir=str(cache_dir), **kw)

    def _client(self, auth):
        pytest.importorskip("fastapi")
        from fastapi import Depends, FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()

        @app.get("/protected")
        def protected(agent: dict = Depends(auth.verify)):  # noqa: B008 — FastAPI idiom
            return {"did": agent["did"], "aud": agent.get("aud", "")}

        return TestClient(app)

    def test_requires_env_or_args(self):
        from hermes_id.fastapi_middleware import HermesIDAuth

        with pytest.raises(ValueError):
            HermesIDAuth(server_url="http://127.0.0.1:1")  # no project
        with pytest.raises(ValueError):
            HermesIDAuth(project="spacetime-test")  # no server

    def test_env_driven_config(self, monkeypatch):
        from hermes_id.fastapi_middleware import HermesIDAuth

        monkeypatch.setenv("HERMES_AUTH_SERVER_URL", "http://127.0.0.1:9999")
        monkeypatch.setenv("HERMES_AUTH_PROJECT", "spacetime-envtest")
        auth = HermesIDAuth()
        assert auth._server_url == "http://127.0.0.1:9999"
        assert auth._project == "spacetime-envtest"

    def test_missing_header_401(self, server_url, auth_cache_dir):
        auth = self._make_auth(server_url, "spacetime-test", auth_cache_dir)
        resp = self._client(auth).get("/protected")
        assert resp.status_code == 401

    def test_invalid_token_401(self, server_url, auth_cache_dir):
        auth = self._make_auth(server_url, "spacetime-test", auth_cache_dir)
        resp = self._client(auth).get("/protected", headers={"Authorization": "Bearer garbage.token"})
        assert resp.status_code == 401

    def test_valid_token_200(self, server_url, token, auth_cache_dir):
        auth = self._make_auth(server_url, "spacetime-test", auth_cache_dir)
        resp = self._client(auth).get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["did"].startswith("did:hermes:")
        assert body["aud"] == "spacetime-test"

    def test_wrong_audience_401(self, server_url, token, auth_cache_dir):
        # The core security guarantee: a token for spacetime-test is rejected
        # by a service scoped to spacetime-other.
        auth = self._make_auth(server_url, "spacetime-other", auth_cache_dir)
        resp = self._client(auth).get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_offline_first_when_server_down(self, server_url, token, tmp_path):
        """With a cached server card, verification works even if the auth
        server is unreachable (offline-first + fail-open revocation)."""
        cache_dir = tmp_path / "auth-cache"
        # Prime the disk cache from the live server
        load_server_card(
            server_url,
            cache_path=default_card_cache_path("http://127.0.0.1:1", str(cache_dir)),
            timeout=2.0,
        )
        # Now construct auth against a DEAD port with that cache dir
        auth = self._make_auth(
            "http://127.0.0.1:1",
            "spacetime-test",
            cache_dir,
            timeout=1.0,
        )
        resp = self._client(auth).get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, resp.text

    def test_check_token_non_raising(self, server_url, token, auth_cache_dir):
        auth = self._make_auth(server_url, "spacetime-test", auth_cache_dir)
        assert auth.check_token(token) is not None
        assert auth.check_token("garbage") is None


class TestHermesIDAuthEnvVerify:
    """HERMES_AUTH_VERIFY env parsing in the FastAPI middleware."""

    def _captured_verify(self, monkeypatch):
        import hermes_id.fastapi_middleware as fm

        captured: dict = {}

        class FakeRevocationChecker:
            def __init__(self, *a, **kw):
                captured["verify"] = kw.get("verify")

            def is_revoked(self, token, token_id):
                return False

        monkeypatch.setattr(fm, "RevocationChecker", FakeRevocationChecker)
        return captured

    def test_verify_env_false(self, monkeypatch, tmp_path):
        from hermes_id.fastapi_middleware import HermesIDAuth

        captured = self._captured_verify(monkeypatch)
        monkeypatch.setenv("HERMES_AUTH_VERIFY", "false")
        HermesIDAuth(
            server_url="http://127.0.0.1:1", project="spacetime-test",
            cache_dir=str(tmp_path),
        )
        assert captured["verify"] is False

    def test_verify_env_true(self, monkeypatch, tmp_path):
        from hermes_id.fastapi_middleware import HermesIDAuth

        captured = self._captured_verify(monkeypatch)
        monkeypatch.setenv("HERMES_AUTH_VERIFY", "yes")
        HermesIDAuth(
            server_url="http://127.0.0.1:1", project="spacetime-test",
            cache_dir=str(tmp_path),
        )
        assert captured["verify"] is True

    def test_verify_env_ca_path(self, monkeypatch, tmp_path):
        from hermes_id.fastapi_middleware import HermesIDAuth

        captured = self._captured_verify(monkeypatch)
        ca = tmp_path / "ca.pem"
        ca.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
        monkeypatch.setenv("HERMES_AUTH_VERIFY", str(ca))
        HermesIDAuth(
            server_url="http://127.0.0.1:1", project="spacetime-test",
            cache_dir=str(tmp_path),
        )
        assert captured["verify"] == str(ca)

    def test_verify_no_env_defaults_true(self, monkeypatch, tmp_path):
        from hermes_id.fastapi_middleware import HermesIDAuth

        captured = self._captured_verify(monkeypatch)
        monkeypatch.delenv("HERMES_AUTH_VERIFY", raising=False)
        HermesIDAuth(
            server_url="http://127.0.0.1:1", project="spacetime-test",
            cache_dir=str(tmp_path),
        )
        assert captured["verify"] is True


class TestHermesIDAuthRevokedPath:
    def test_revoked_token_raises_autherror(self, server_url, token, auth_cache_dir, monkeypatch):
        """A token reported revoked by the checker → AuthError('revoked')."""
        import hermes_id.sdk as sdk
        from hermes_id.fastapi_middleware import HermesIDAuth

        auth = HermesIDAuth(server_url=server_url, project="spacetime-test", cache_dir=str(auth_cache_dir))

        class FakeRevoked:
            def is_revoked(self, token, token_id):
                return True

        monkeypatch.setattr(auth, "_revocation", FakeRevoked())
        with pytest.raises(sdk.AuthError) as exc:
            auth.verify_token(token)
        assert exc.value.reason == "revoked"


# ---------------------------------------------------------------------------
# fastapi_plugin — drop-in agent-auth router
# ---------------------------------------------------------------------------

class TestFastAPIPlugin:
    def _make_app(self, server_url, project, auth_cache_dir):
        pytest.importorskip("fastapi")
        from fastapi import FastAPI

        from hermes_id.fastapi_middleware import HermesIDAuth
        from hermes_id.fastapi_plugin import install_agent_auth

        app = FastAPI()
        install_agent_auth(app, auth=HermesIDAuth(
            server_url=server_url, project=project, cache_dir=str(auth_cache_dir)
        ))
        return app

    def _client(self, app):
        from fastapi.testclient import TestClient

        return TestClient(app)

    def test_status_public(self, server_url, auth_cache_dir):
        app = self._make_app(server_url, "spacetime-test", auth_cache_dir)
        resp = self._client(app).get("/hermes-id/agent/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["configured"] is True
        assert body["project"] == "spacetime-test"
        assert body["server_card_cached"] is True
        # The auth-server URL is deliberately NOT exposed to unauthenticated
        # callers (privacy hardening).
        assert "auth_server_url" not in body

    def test_me_requires_token(self, server_url, auth_cache_dir):
        app = self._make_app(server_url, "spacetime-test", auth_cache_dir)
        resp = self._client(app).get("/hermes-id/agent/me")
        assert resp.status_code == 401

    def test_me_with_valid_token(self, server_url, token, auth_cache_dir):
        app = self._make_app(server_url, "spacetime-test", auth_cache_dir)
        resp = self._client(app).get(
            "/hermes-id/agent/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["authenticated"] is True
        assert body["did"].startswith("did:hermes:")
        assert body["aud"] == "spacetime-test"

    def test_me_wrong_audience_401(self, server_url, token, auth_cache_dir):
        app = self._make_app(server_url, "spacetime-other", auth_cache_dir)
        resp = self._client(app).get(
            "/hermes-id/agent/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401

    def test_env_driven_install(self, monkeypatch, server_url, token, auth_cache_dir):
        pytest.importorskip("fastapi")
        from fastapi import FastAPI

        from hermes_id.fastapi_plugin import install_agent_auth

        monkeypatch.setenv("HERMES_AUTH_SERVER_URL", server_url)
        monkeypatch.setenv("HERMES_AUTH_PROJECT", "spacetime-test")
        monkeypatch.setenv("HERMES_AUTH_CACHE_DIR", str(auth_cache_dir))
        # install_agent_auth reads env; cache_dir comes through HermesIDAuth env
        import os

        from hermes_id.fastapi_middleware import HermesIDAuth

        app = FastAPI()
        install_agent_auth(app, auth=HermesIDAuth(
            server_url=os.environ["HERMES_AUTH_SERVER_URL"],
            project=os.environ["HERMES_AUTH_PROJECT"],
            cache_dir=str(auth_cache_dir),
        ))
        from fastapi.testclient import TestClient

        resp = TestClient(app).get(
            "/hermes-id/agent/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200

    def test_status_graceful_when_card_load_fails(self, tmp_path, monkeypatch):
        """agent_status stays 200 and reports server_card_cached=False when
        the server card can't be loaded."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from hermes_id.fastapi_plugin import build_agent_router

        class BoomAuth:
            _server_url = "http://127.0.0.1:1"
            _project = "spacetime-test"

            def get_server_card(self):
                raise RuntimeError("server unreachable")

            def verify(self, authorization=None):
                raise RuntimeError("not reached")

        app = FastAPI()
        app.include_router(build_agent_router(BoomAuth()), prefix="/hermes-id")
        resp = TestClient(app).get("/hermes-id/agent/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["server_card_cached"] is False
        assert body["server_did"] == ""


# ---------------------------------------------------------------------------
# TokenCache — per-project persistent token cache
# ---------------------------------------------------------------------------

class TestTokenCache:
    def test_round_trip(self, tmp_path):
        cache = TokenCache("spacetime-tv", directory=str(tmp_path))
        assert cache.get() is None
        cache.put("tok123", {"did": "did:hermes:x", "expires_at": 9999999999})
        token, payload = cache.get()
        assert token == "tok123"
        assert payload["did"] == "did:hermes:x"

    def test_clear(self, tmp_path):
        cache = TokenCache("spacetime-tv", directory=str(tmp_path))
        cache.put("tok123", {"did": "d"})
        cache.clear()
        assert cache.get() is None

    def test_per_project_isolation(self, tmp_path):
        a = TokenCache("spacetime-tv", directory=str(tmp_path))
        b = TokenCache("spacetime-air", directory=str(tmp_path))
        a.put("tv-token", {"did": "d"})
        assert b.get() is None
        assert str(a.path).endswith("spacetime-tv.json")

    def test_requires_project(self):
        with pytest.raises(ValueError):
            TokenCache("")


# ---------------------------------------------------------------------------
# Edge-case coverage — malformed cards, env TLS parsing, cache failures,
# TokenCache failure modes (the defensive paths).
# ---------------------------------------------------------------------------

class TestVerifyTokenOfflineMalformedInputs:
    def test_invalid_json_string_card_rejected(self, token):
        assert verify_token_offline(token, "definitely not a card") is None

    def test_invalid_dict_card_rejected(self, token):
        assert verify_token_offline(token, {"not": "a card"}) is None

    def test_unparseable_payload_rejected(self, server_identity):
        """A token whose payload base64-decodes but isn't JSON → None."""
        from hermes_id.crypto import _b64, sign
        from hermes_id.storage import IdentityStorage

        storage = IdentityStorage(directory=server_identity)
        private = storage.unlock(_TEST_PASSWORD)
        raw_payload = b"this is not json"
        payload_b64 = _b64(raw_payload)
        sig = sign(private, raw_payload)
        token = f"{payload_b64}.{_b64(sig)}"

        card = storage.get_identity_card()
        assert verify_token_offline(token, card.to_json()) is None

    def test_card_with_bad_public_key_rejected(self, token, server_card):
        bad = dict(server_card)
        bad["verification_method"] = [{
            "id": "x", "type": "Ed25519VerificationKey2020",
            "controller": bad["id"],
            "publicKeyMultibase": "uzzz",  # garbage multibase
        }]
        assert verify_token_offline(token, bad) is None


class TestLoadServerCardEdgeCases:
    def test_corrupt_cache_ignored_when_server_up(self, server_url, tmp_path):
        cache = tmp_path / "card.json"
        cache.write_text("{{{corrupt json")
        card = load_server_card(server_url, cache_path=cache)
        assert card["id"].startswith("did:hermes:")

    def test_env_verify_false_disables_tls(self, server_url, tmp_path, monkeypatch):

        monkeypatch.setenv("HERMES_AUTH_VERIFY", "false")
        captured: dict = {}
        real_get = httpx.get

        def fake_get(url, **kwargs):
            captured["verify"] = kwargs.get("verify")
            return real_get(url, **kwargs)

        monkeypatch.setattr(httpx, "get", fake_get)
        load_server_card(server_url, cache_path=tmp_path / "c.json")
        assert captured["verify"] is False

    def test_env_verify_0_disables_tls(self, server_url, tmp_path, monkeypatch):

        monkeypatch.setenv("HERMES_AUTH_VERIFY", "0")
        captured: dict = {}
        real_get = httpx.get

        def fake_get(url, **kwargs):
            captured["verify"] = kwargs.get("verify")
            return real_get(url, **kwargs)

        monkeypatch.setattr(httpx, "get", fake_get)
        load_server_card(server_url, cache_path=tmp_path / "c.json")
        assert captured["verify"] is False

    def test_env_verify_path_used_as_ca_bundle(self, server_url, server_card, tmp_path, monkeypatch):

        ca_path = "/opt/example/ca.pem"
        monkeypatch.setenv("HERMES_AUTH_VERIFY", ca_path)
        captured: dict = {}

        class FakeResp:
            def raise_for_status(self):
                pass

            def json(self):
                return server_card

        def fake_get(url, **kwargs):
            captured["verify"] = kwargs.get("verify")
            return FakeResp()

        monkeypatch.setattr(httpx, "get", fake_get)
        load_server_card(server_url, cache_path=tmp_path / "c.json")
        assert captured["verify"] == ca_path

    def test_card_failing_self_signature_raises(self, server_card, tmp_path, monkeypatch):

        bad = dict(server_card)
        bad["proof"]["signatureValue"] = bad["proof"]["signatureValue"][:-4] + "AAAA"

        class FakeResp:
            def raise_for_status(self):
                pass

            def json(self):
                return bad

        monkeypatch.setattr(httpx, "get", lambda url, **kw: FakeResp())
        with pytest.raises(AuthError):
            load_server_card("http://x", cache_path=tmp_path / "c.json", allow_stale=False)

    def test_cache_write_failure_is_best_effort(self, server_url, tmp_path, monkeypatch):
        def boom(*a, **kw):
            raise OSError("read-only filesystem")

        monkeypatch.setattr(Path, "write_text", boom)
        card = load_server_card(server_url, cache_path=tmp_path / "card.json")
        assert card["id"].startswith("did:hermes:")


class TestTokenCacheFailureModes:
    def test_get_empty_token_returns_none(self, tmp_path):
        d = tmp_path / "tokens"
        d.mkdir()
        (d / "proj.json").write_text('{"token": "", "payload": {}}')
        assert TokenCache("proj", directory=str(d)).get() is None

    def test_get_corrupt_file_returns_none(self, tmp_path):
        d = tmp_path / "tokens"
        d.mkdir()
        (d / "proj.json").write_text("not json at all")
        assert TokenCache("proj", directory=str(d)).get() is None

    def test_put_oserror_suppressed(self, tmp_path, monkeypatch):
        def boom(*a, **kw):
            raise OSError("disk full")

        monkeypatch.setattr(Path, "write_text", boom)
        tc = TokenCache("proj", directory=str(tmp_path / "tokens"))
        tc.put("tok", {"did": "x"})  # must not raise

    def test_clear_missing_file_no_raise(self, tmp_path):
        tc = TokenCache("proj", directory=str(tmp_path / "tokens"))
        tc.clear()  # must not raise


# ---------------------------------------------------------------------------
# Remaining SDK branches — card key extraction, cache freshness edge cases
# ---------------------------------------------------------------------------


class TestCardPublicKeyBytes:
    def test_no_public_key_returns_none(self):
        from hermes_id.identity import IdentityCard
        from hermes_id.sdk import _card_public_key_bytes

        card = IdentityCard(
            id="did:hermes:x",
            controller="did:hermes:x",
            verification_method=[{"publicKeyMultibase": ""}],
            authentication=[],
            assertion_method=[],
            created="2026-01-01T00:00:00Z",
        )
        assert _card_public_key_bytes(card) is None

    def test_empty_pubkey_returns_none(self):
        from hermes_id.identity import IdentityCard
        from hermes_id.sdk import _card_public_key_bytes

        card = IdentityCard(
            id="did:hermes:x",
            controller="did:hermes:x",
            verification_method=[],
            authentication=[],
            assertion_method=[],
            created="2026-01-01T00:00:00Z",
        )
        assert _card_public_key_bytes(card) is None

    def test_unparseable_multibase_returns_none(self, server_card, monkeypatch):
        from hermes_id.identity import IdentityCard
        from hermes_id.sdk import _card_public_key_bytes

        # A card whose multibase body isn't valid base64
        card = IdentityCard.from_json(json.dumps(server_card))
        data = json.loads(card.to_json())
        data["verification_method"][0]["publicKeyMultibase"] = "u%%%%"
        card2 = IdentityCard.from_json(json.dumps(data))
        assert _card_public_key_bytes(card2) is None

    def test_no_multibase_prefix_skips_strip(self, server_card):
        """A card whose public key is bare base64url (no 'u' multibase
        prefix) is decoded directly — covers the startswith==False branch."""
        import base64

        from hermes_id.identity import IdentityCard
        from hermes_id.sdk import _card_public_key_bytes

        # Round-trip the fixture card and replace the public key with a bare
        # base64url value (no "u" multibase prefix). Decoding it must return
        # exactly the bytes we put in — independent of the fixture's key.
        card = IdentityCard.from_json(json.dumps(server_card))
        data = json.loads(card.to_json())
        pub_bytes = b"\x01\x02\x03\x04" + b"\x05" * 28  # 32-byte Ed25519 key
        bare_b64 = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
        data["verification_method"][0]["publicKeyMultibase"] = bare_b64  # no "u" prefix
        card2 = IdentityCard.from_json(json.dumps(data))
        assert _card_public_key_bytes(card2) == pub_bytes


class TestVerifyOfflineNoPubkey:
    def test_card_without_pubkey_rejected(self):
        from hermes_id.identity import IdentityCard
        from hermes_id.sdk import verify_token_offline

        # A structurally-valid card with no public key → no pubkey path.
        # Use valid-base64 parts so the token parses and the no-pubkey
        # check is reached (not a base64 decode abort).
        card = IdentityCard(
            id="did:hermes:x",
            controller="did:hermes:x",
            verification_method=[],
            authentication=[],
            assertion_method=[],
            created="2026-01-01T00:00:00Z",
        )
        assert verify_token_offline("AAAA.AAAA", card) is None

    def test_dict_card_without_pubkey_rejected(self):
        from hermes_id.identity import IdentityCard
        from hermes_id.sdk import verify_token_offline

        # Dict form of a card with empty verification_method
        card = IdentityCard(
            id="did:hermes:x",
            controller="did:hermes:x",
            verification_method=[],
            authentication=[],
            assertion_method=[],
            created="2026-01-01T00:00:00Z",
        )
        data = json.loads(card.to_json())
        assert verify_token_offline("AAAA.AAAA", data) is None


class TestServerCardVerifyEnvTrue:
    def test_env_verify_true_keeps_tls(self, server_url, tmp_path, monkeypatch):
        """HERMES_AUTH_VERIFY=true leaves TLS verification on."""
        monkeypatch.setenv("HERMES_AUTH_VERIFY", "true")
        captured: dict = {}
        real_get = httpx.get

        def fake_get(url, **kwargs):
            captured["verify"] = kwargs.get("verify")
            return real_get(url, **kwargs)

        monkeypatch.setattr(httpx, "get", fake_get)
        load_server_card(server_url, cache_path=tmp_path / "c.json")
        assert captured["verify"] is True


class TestLoadServerCardCacheValidity:
    def test_invalid_signed_cache_rejected(self, server_url, server_card, tmp_path, monkeypatch):
        """A cached card that fails self-signature is not trusted."""
        # Prime a cache file containing a bad card, then bring the server down
        bad = dict(server_card)
        bad["proof"]["signatureValue"] = bad["proof"]["signatureValue"][:-4] + "AAAA"
        cache = tmp_path / "card.json"
        cache.write_text(json.dumps(bad))

        # Server unreachable
        class BoomResp:
            def raise_for_status(self):
                raise httpx.ConnectError("down")

        monkeypatch.setattr(httpx, "get", lambda url, **kw: BoomResp())
        with pytest.raises(AuthError):
            load_server_card(
                "http://127.0.0.1:1", cache_path=cache, allow_stale=False,
            )

    def test_invalid_signed_cache_not_returned(self, server_card, tmp_path):
        """verify_token_offline with a signed-invalid cached card returns None."""

        bad = dict(server_card)
        bad["proof"]["signatureValue"] = bad["proof"]["signatureValue"][:-4] + "AAAA"
        # verify_identity_card would fail, so treat it as no trusted card
        from hermes_id.sdk import _card_public_key_bytes

        assert _card_public_key_bytes(
            type("C", (), {"public_key_multibase": property(lambda self: "")})()
        ) is None


class TestCacheStatOSError:
    def test_stat_failure_falls_through_to_network(self, server_card, tmp_path, monkeypatch):
        """An OSError from the freshness stat() is ignored — the code
        falls through to a network fetch rather than raising."""
        cache = tmp_path / "card.json"
        cache.write_text(json.dumps(server_card))  # valid cached card

        fetched: dict = {"count": 0}
        real_stat = Path.stat
        stats: dict = {"n": 0}

        def flaky_stat(self, *a, **kw):
            # 1st call = Path.exists() inside _load_cache → must succeed
            # 2nd call = freshness check after a valid cache → raise OSError
            stats["n"] += 1
            if stats["n"] >= 2:
                raise OSError("stat failed")
            return real_stat(self, *a, **kw)

        monkeypatch.setattr(Path, "stat", flaky_stat)

        class FakeResp:
            def raise_for_status(self):
                pass

            def json(self):
                fetched["count"] += 1
                return server_card

        monkeypatch.setattr(httpx, "get", lambda url, **kw: FakeResp())
        card2 = load_server_card("http://127.0.0.1:1", cache_path=cache)
        assert card2["id"].startswith("did:hermes:")
        assert fetched["count"] >= 1  # fell through to the network
