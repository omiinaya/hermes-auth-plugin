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
            rate_limit_max=100,
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
