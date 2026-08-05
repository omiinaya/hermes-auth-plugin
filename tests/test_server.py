"""Tests for the hermes-id Auth Server (FastAPI)."""

import contextlib
import os
import threading
import time

import httpx
import pytest

from hermes_id.auth_client import AuthClient
from hermes_id.crypto import _b64
from hermes_id.storage import IdentityStorage

_TEST_PASSWORD = "hermes-id-test-password-2026"

# Set the test password in the environment so AuthClient can find it
os.environ["HERMES_ID_PASSPHRASE"] = _TEST_PASSWORD

@pytest.fixture(scope="module")
def server_identity(tmp_path_factory):
    """Create a standalone identity for the test server."""
    identity_dir = tmp_path_factory.mktemp("server-identity")
    storage = IdentityStorage(directory=str(identity_dir))
    storage.create(_TEST_PASSWORD, metadata={"profile": "test-server"})
    return str(identity_dir)


@pytest.fixture(scope="module")
def client_identity(tmp_path_factory):
    """Create an identity for a test agent."""
    identity_dir = tmp_path_factory.mktemp("client-identity")
    storage = IdentityStorage(directory=str(identity_dir))
    storage.create(_TEST_PASSWORD, metadata={"profile": "test-agent"})
    return str(identity_dir)


@pytest.fixture(scope="module")
def auth_server(server_identity, tmp_path_factory):
    """Start the auth server in a background thread."""
    db_path = tmp_path_factory.mktemp("data") / "test_registry.db"
    from hermes_id.server import AuthServer

    admin_key = "test-admin-key-for-tests"
    server = AuthServer(
        identity_dir=server_identity,
        db_path=str(db_path),
        token_ttl=3600,
        challenge_ttl=60,
        admin_key=admin_key,
        cors_origins=["*"],
        # Module-scoped server accumulates /challenge calls across many
        # tests — 100 trips 429 spuriously under some orderings. The limiter
        # is tested in test_server_edges, not here.
        rate_limit_max=5000,
    )

    # Bind an ephemeral port (0) so concurrent test runs / leftover
    # processes can never collide on a hardcoded port. The pre-bound
    # socket is handed to uvicorn by fd — no race between discovery
    # and bind.
    import socket as _socket

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    import uvicorn
    t = threading.Thread(
        target=lambda: uvicorn.run(server.app, host="127.0.0.1", port=port, log_level="error", fd=sock.fileno()),
        daemon=True,
    )
    t.start()
    time.sleep(2)

    yield {"port": port, "db_path": db_path, "admin_key": admin_key, "server": server}

    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def server_url(auth_server):
    return f"http://127.0.0.1:{auth_server['port']}"


@pytest.fixture
def admin_client(server_url):
    return AuthClient(server_url, admin_key="test-admin-key-for-tests")


@pytest.fixture
def agent_client(server_url, client_identity):
    return AuthClient(server_url, identity_dir=client_identity)


@pytest.fixture(autouse=True)
def register_and_approve(agent_client, admin_client):
    """Ensure the test agent is registered and approved before each test."""
    card = agent_client._storage.get_identity_card()
    with contextlib.suppress(httpx.HTTPStatusError):
        agent_client.register_agent(card.id, display_name="Test Agent")
    with contextlib.suppress(httpx.HTTPStatusError):
        admin_client.approve_agent(card.id)
    yield


# ---------------------------------------------------------------------------
# Health & Identity
# ---------------------------------------------------------------------------

class TestServerHealth:
    def test_health(self, server_url):
        client = AuthClient(server_url)
        h = client.health()
        assert h["status"] == "ok"
        assert h["did"].startswith("did:hermes:")
        # uptime must be a real elapsed-seconds value (not the epoch — that
        # bug shipped a ~1.7e9 number and was fixed in 1.5.0), and it must
        # grow between two calls.
        assert 0 <= h["uptime"] < 3600, f"uptime looks like epoch: {h['uptime']}"
        import time as _time

        _time.sleep(1.1)
        h2 = client.health()
        assert h2["uptime"] > h["uptime"]

    def test_identity(self, server_url):
        client = AuthClient(server_url)
        identity = client.get_identity()
        assert identity["id"].startswith("did:hermes:")
        assert "verification_method" in identity
        assert "proof" in identity


# ---------------------------------------------------------------------------
# Agent Registry
# ---------------------------------------------------------------------------

class TestAgentRegistry:
    def test_list_agents(self, admin_client):
        agents = admin_client.list_agents()
        assert agents["total"] >= 1
        assert "page" in agents
        assert "pages" in agents

    def test_register_duplicate_fails(self, agent_client):
        card = agent_client._storage.get_identity_card()
        with pytest.raises(httpx.HTTPStatusError) as exc:
            agent_client.register_agent(card.id)
        assert exc.value.response.status_code == 409

    def test_approve_twice_fails(self, agent_client, admin_client):
        card = agent_client._storage.get_identity_card()
        with pytest.raises(httpx.HTTPStatusError) as exc:
            admin_client.approve_agent(card.id)
        assert exc.value.response.status_code == 409

    def test_get_status(self, admin_client, agent_client):
        card = agent_client._storage.get_identity_card()
        status = admin_client.get_agent_status(card.id)
        assert status["did"] == card.id
        assert status["status"] in ("approved", "pending")

    def test_admin_key_required(self, server_url):
        client_no_key = AuthClient(server_url)
        with pytest.raises(httpx.HTTPStatusError) as exc:
            client_no_key.approve_agent("did:hermes:fake")
        assert exc.value.response.status_code == 403

    def test_search_agents(self, admin_client):
        agents = admin_client.list_agents(search="Test")
        assert agents["total"] >= 1

    def test_list_pagination(self, admin_client):
        agents = admin_client.list_agents(page=1, page_size=10)
        assert agents["page"] == 1
        assert agents["page_size"] == 10

    def test_delete_agent(self, server_url):
        import tempfile
        tmp_dir = tempfile.mkdtemp()
        tmp_storage = IdentityStorage(directory=tmp_dir)
        tmp_storage.create("tmp-pass-delete", metadata={"profile": "tmp"})
        tmp_card = tmp_storage.get_identity_card()

        tmp_client = AuthClient(server_url, identity_dir=tmp_dir)
        admin = AuthClient(server_url, admin_key="test-admin-key-for-tests")

        tmp_client.register_agent(tmp_card.id, display_name="To Delete")
        admin.approve_agent(tmp_card.id)
        r = admin.delete_agent(tmp_card.id)
        assert r["status"] == "deleted"


# ---------------------------------------------------------------------------
# Authentication Flow
# ---------------------------------------------------------------------------

class TestAuthentication:
    def test_challenge(self, agent_client):
        card = agent_client._storage.get_identity_card()
        chal = agent_client.challenge(card.id)
        assert "challenge_b64" in chal
        assert "expires_at" in chal
        assert chal["server_did"].startswith("did:hermes:")

    def test_full_auth_flow(self, agent_client):
        card = agent_client._storage.get_identity_card()
        chal = agent_client.challenge(card.id)
        sig = agent_client.sign_challenge(chal["challenge_b64"])
        result = agent_client.authenticate(card.id, chal["challenge_b64"], sig)
        assert "token" in result
        assert "token_id" in result
        assert result["did"] == card.id

    def test_verify_token(self, agent_client):
        card = agent_client._storage.get_identity_card()
        chal = agent_client.challenge(card.id)
        sig = agent_client.sign_challenge(chal["challenge_b64"])
        result = agent_client.authenticate(card.id, chal["challenge_b64"], sig)
        v = agent_client.verify_token(result["token"])
        assert v is not None
        assert v["valid"] is True
        assert v["did"] == card.id

    def test_refresh_token(self, agent_client):
        card = agent_client._storage.get_identity_card()
        chal = agent_client.challenge(card.id)
        sig = agent_client.sign_challenge(chal["challenge_b64"])
        result = agent_client.authenticate(card.id, chal["challenge_b64"], sig)
        refreshed = agent_client.refresh_token(result["token"])
        assert refreshed is not None
        assert "token" in refreshed
        assert refreshed["did"] == card.id

    def test_revoke_and_verify_fails(self, agent_client):
        card = agent_client._storage.get_identity_card()
        chal = agent_client.challenge(card.id)
        sig = agent_client.sign_challenge(chal["challenge_b64"])
        result = agent_client.authenticate(card.id, chal["challenge_b64"], sig)
        assert agent_client.revoke_token(result["token"]) is True
        v = agent_client.verify_token(result["token"])
        assert v is None or v.get("valid") is False

    def test_tampered_token_fails(self, agent_client):
        card = agent_client._storage.get_identity_card()
        chal = agent_client.challenge(card.id)
        sig = agent_client.sign_challenge(chal["challenge_b64"])
        result = agent_client.authenticate(card.id, chal["challenge_b64"], sig)
        parts = result["token"].split(".")
        tampered = parts[0] + "." + parts[1][:-5] + "AAAAA"
        v = agent_client.verify_token(tampered)
        assert v is None or v.get("valid") is False

    def test_bad_signature_rejected(self, agent_client):
        card = agent_client._storage.get_identity_card()
        chal = agent_client.challenge(card.id)
        with pytest.raises(httpx.HTTPStatusError) as exc:
            agent_client.authenticate(card.id, chal["challenge_b64"], "AAAAAA")
        assert exc.value.response.status_code in (400, 401)


# ---------------------------------------------------------------------------
# Authorization (access control)
# ---------------------------------------------------------------------------

class TestAuthorization:
    def test_unregistered_agent_fails(self, server_url):
        """An agent not in the registry should fail auth. Sign manually."""
        import tempfile

        from hermes_id.crypto import sign as ed_sign

        tmp_dir = tempfile.mkdtemp()
        tmp_storage = IdentityStorage(directory=tmp_dir)
        tmp_storage.create("tmp-pass-unauth")
        tmp_card = tmp_storage.get_identity_card()

        # Sign the challenge manually (different password from env)
        unauth_client = AuthClient(server_url)  # no identity_dir
        chal = unauth_client.challenge(tmp_card.id)

        with tmp_storage.use_key("tmp-pass-unauth") as pk:
            from hermes_id.crypto import _unb64 as _ub
            sig = ed_sign(pk, _ub(chal["challenge_b64"]))

        with pytest.raises(httpx.HTTPStatusError) as exc:
            unauth_client.authenticate(
                tmp_card.id, chal["challenge_b64"], _b64(sig),
                identity_card=tmp_card.to_json(),
            )
        assert exc.value.response.status_code == 403

    def test_denied_agent_fails(self, server_url, admin_client):
        """A denied agent should fail auth. Sign manually."""
        import tempfile

        from hermes_id.crypto import _unb64 as _ub
        from hermes_id.crypto import sign as ed_sign

        tmp_dir = tempfile.mkdtemp()
        tmp_storage = IdentityStorage(directory=tmp_dir)
        tmp_storage.create("tmp-pass-denied")
        tmp_card = tmp_storage.get_identity_card()

        tmp_client = AuthClient(server_url)  # no identity_dir
        tmp_client.register_agent(
            tmp_card.id, identity_card=tmp_card.to_json(), display_name="To Deny"
        )
        admin_client.deny_agent(tmp_card.id)

        chal = tmp_client.challenge(tmp_card.id)
        with tmp_storage.use_key("tmp-pass-denied") as pk:
            sig = ed_sign(pk, _ub(chal["challenge_b64"]))

        with pytest.raises(httpx.HTTPStatusError) as exc:
            tmp_client.authenticate(
                tmp_card.id, chal["challenge_b64"], _b64(sig),
                identity_card=tmp_card.to_json(),
            )
        assert exc.value.response.status_code == 403


# ---------------------------------------------------------------------------
# AuthFlow convenience
# ---------------------------------------------------------------------------

class TestAuthFlow:
    def test_login(self, server_url, client_identity, admin_client):
        from hermes_id.auth_client import AuthFlow

        auth_cli = AuthClient(server_url, identity_dir=client_identity)
        card = auth_cli._storage.get_identity_card()
        with contextlib.suppress(httpx.HTTPStatusError):
            auth_cli.register_agent(card.id)
        with contextlib.suppress(httpx.HTTPStatusError):
            admin_client.approve_agent(card.id)
        auth_cli.close()

        flow = AuthFlow(server_url, identity_dir=client_identity)
        token, result = flow.login()
        assert len(token) > 20
        assert result["did"] == card.id
        flow.close()

    def test_login_round_trip(self, server_url, client_identity, admin_client):
        """Full round-trip: login, verify, verify via server."""
        from hermes_id.auth_client import AuthFlow

        flow = AuthFlow(server_url, identity_dir=client_identity)
        token, _ = flow.login()
        flow.close()

        client = AuthClient(server_url)
        v = client.verify_token(token)
        assert v is not None
        assert v["valid"] is True
        client.close()


class TestTLSSupport:
    """Auth server can serve HTTPS with a PEM cert/key pair."""

    @staticmethod
    def _start_tls(app, cert, key, host: str = "127.0.0.1"):
        """Start a TLS uvicorn server on an EPHEMERAL port (0) so tests
        never collide with each other or with concurrent runs (the old
        hardcoded 9496/9497 fixtures collided in the full suite)."""
        import uvicorn

        config = uvicorn.Config(
            app, host=host, port=0, log_level="error",
            ssl_certfile=cert, ssl_keyfile=key,
        )
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

        return port, stop

    def _gen_cert(self, tmp_path):
        """Generate a self-signed cert for localhost."""
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        return str(cert_path), str(key_path)

    def test_https_serves_identity(self, server_identity, tmp_path):
        cert, key = self._gen_cert(tmp_path)
        from hermes_id.server import AuthServer

        db_path = tmp_path / "tls_registry.db"
        server = AuthServer(identity_dir=server_identity, db_path=str(db_path), admin_key="k")
        port, stop = self._start_tls(server.app, cert, key)
        try:
            import ssl as ssl_mod
            import urllib.request
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
            with urllib.request.urlopen(f"https://127.0.0.1:{port}/identity", context=ctx, timeout=5) as r:
                body = r.read().decode()
                assert r.status == 200
                assert "did:hermes:" in body
        finally:
            stop()

    def test_plain_http_fails_on_tls_port(self, server_identity, tmp_path):
        cert, key = self._gen_cert(tmp_path)
        from hermes_id.server import AuthServer

        db_path = tmp_path / "tls_registry2.db"
        server = AuthServer(identity_dir=server_identity, db_path=str(db_path), admin_key="k")
        port, stop = self._start_tls(server.app, cert, key)
        try:
            import httpx
            with pytest.raises(Exception):
                httpx.get(f"http://127.0.0.1:{port}/identity", timeout=3)
        finally:
            stop()


# ---------------------------------------------------------------------------
# Audience scoping enforcement — regression: an agent approved ONLY for
# project X must NOT be able to mint tokens scoped for project Y via
# /authenticate. (Security fix: previously the aud was taken from the
# request unchecked, defeating per-project approval.)
# ---------------------------------------------------------------------------

class TestAudienceScoping:
    def test_agent_cannot_mint_token_for_unapproved_project(
        self, server_url, admin_client, tmp_path_factory
    ):
        from hermes_id.auth_client import AuthClient, AuthFlow

        # Fresh agent registered + approved ONLY for spacetime-tv
        scoped_dir = str(tmp_path_factory.mktemp("scoped-agent"))
        storage = IdentityStorage(directory=scoped_dir)
        storage.create(_TEST_PASSWORD, metadata={"profile": "scoped-agent"})
        card = storage.get_identity_card()

        agent = AuthClient(server_url, identity_dir=scoped_dir)
        with contextlib.suppress(httpx.HTTPStatusError):
            agent.register_agent(
                card.id, display_name="Scoped Agent", projects=["spacetime-tv"]
            )
        admin_client.approve_agent(card.id, project="spacetime-tv")

        flow = AuthFlow(server_url, identity_dir=scoped_dir)

        # Correct aud → token issued, scoped to the approved project
        token, result = flow.login(aud="spacetime-tv")
        assert result["aud"] == "spacetime-tv"
        assert token

        # Unapproved aud → 403 (the security fix)
        with pytest.raises(httpx.HTTPStatusError) as exc:
            flow.login(aud="spacetime-air")
        assert exc.value.response.status_code == 403

        # Unscoped token (aud="") still allowed — no audience escalation
        _, result2 = flow.login(aud=None)
        assert result2["aud"] == ""

    def test_global_agent_can_request_any_aud(self, server_url, admin_client, tmp_path_factory):
        from hermes_id.auth_client import AuthClient, AuthFlow

        # Agent with NO projects is a global agent — any aud is permitted
        scoped_dir = str(tmp_path_factory.mktemp("global-agent"))
        storage = IdentityStorage(directory=scoped_dir)
        storage.create(_TEST_PASSWORD, metadata={"profile": "global-agent"})
        card = storage.get_identity_card()

        agent = AuthClient(server_url, identity_dir=scoped_dir)
        with contextlib.suppress(httpx.HTTPStatusError):
            agent.register_agent(card.id, display_name="Global Agent")
        admin_client.approve_agent(card.id)

        flow = AuthFlow(server_url, identity_dir=scoped_dir)
        _, result = flow.login(aud="spacetime-air")
        assert result["aud"] == "spacetime-air"


class TestServerBannerVersion:
    def test_startup_banner_reports_real_version(self, server_identity, tmp_path, capsys, monkeypatch):
        """The startup banner must report the real package version, not a
        hardcoded string (regression: it was pinned to 'v1.2.0' while the
        package moved to 1.4.0 and the health endpoint was already fixed)."""
        import builtins

        from hermes_id import __version__
        from hermes_id.server import AuthServer

        db_path = tmp_path / "banner.db"
        srv = AuthServer(identity_dir=server_identity, db_path=str(db_path), admin_key="k")

        calls: dict = {}
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "uvicorn":
                class FakeUvicorn:
                    @staticmethod
                    def run(*a2, **kw2):
                        calls["ran"] = True
                        return None

                return FakeUvicorn()
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        srv.run(host="127.0.0.1", port=7999)

        out = capsys.readouterr().out
        assert f"v{__version__}" in out  # banner reports the real version
        assert "v1.2.0" not in out  # stale hardcode gone
        assert calls.get("ran") is True
