"""Focused tests for AuthClient branches not covered by the live-server
integration tests in test_server.py / test_sdk.py.

Covers: HERMES_AUTH_VERIFY env parsing edge cases, sign_challenge /
get_identity_card_json without identity or password, refresh_token 401
path, and list_agents query-param forwarding. Uses httpx.MockTransport
so no server is needed.
"""

import httpx
import pytest


def _make_client(responses, **kwargs):
    """Build an AuthClient whose httpx client uses MockTransport.

    responses: list of (status_code, json_body) consumed in order.
    Returns (client, requests_list) where requests_list collects every
    httpx.Request sent.
    """
    from hermes_id.auth_client import AuthClient

    client = AuthClient("http://auth.test", admin_key="admin-key", **kwargs)
    seq = iter(responses)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        status, body = next(seq)
        return httpx.Response(status, json=body, request=request)

    client._client = httpx.Client(
        base_url="http://auth.test",
        transport=httpx.MockTransport(handler),
    )
    return client, requests


def _captured_verify(monkeypatch):
    """Return the verify value AuthClient passes to httpx.Client."""
    from hermes_id import auth_client as ac

    captured: dict = {}

    class FakeClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            captured["verify"] = kwargs.get("verify")
            # Don't actually connect; use a mock transport
            kwargs["transport"] = httpx.MockTransport(
                lambda request: httpx.Response(200, json={}, request=request)
            )
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(ac.httpx, "Client", FakeClient)
    return captured


class TestEnvVerifyParsing:
    def test_verify_true_string(self, monkeypatch):
        """HERMES_AUTH_VERIFY=true keeps verification on."""
        from hermes_id.auth_client import AuthClient

        captured = _captured_verify(monkeypatch)
        monkeypatch.setenv("HERMES_AUTH_VERIFY", "true")
        client = AuthClient("http://auth.test")
        client.close()
        assert captured["verify"] is True

    def test_verify_no_string(self, monkeypatch):
        """HERMES_AUTH_VERIFY=no disables verification."""
        from hermes_id.auth_client import AuthClient

        captured = _captured_verify(monkeypatch)
        monkeypatch.setenv("HERMES_AUTH_VERIFY", "no")
        client = AuthClient("http://auth.test")
        client.close()
        assert captured["verify"] is False

    def test_verify_ca_bundle_path(self, monkeypatch, tmp_path):
        """HERMES_AUTH_VERIFY pointing at a file sets the CA bundle."""
        from hermes_id.auth_client import AuthClient

        captured = _captured_verify(monkeypatch)
        ca = tmp_path / "ca.pem"
        ca.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
        monkeypatch.setenv("HERMES_AUTH_VERIFY", str(ca))
        client = AuthClient("http://auth.test")
        client.close()
        assert captured["verify"] == str(ca)

    def test_verify_unknown_string_falls_through(self, monkeypatch):
        """An unrecognized HERMES_AUTH_VERIFY value is treated as a path."""
        from hermes_id.auth_client import AuthClient

        captured = _captured_verify(monkeypatch)
        monkeypatch.setenv("HERMES_AUTH_VERIFY", "/tmp/some-bundle.pem")
        client = AuthClient("http://auth.test")
        client.close()
        assert captured["verify"] == "/tmp/some-bundle.pem"

    def test_verify_env_overrides_explicit_true(self, monkeypatch):
        """Env takes precedence over an explicit verify=True arg."""
        from hermes_id.auth_client import AuthClient

        captured = _captured_verify(monkeypatch)
        monkeypatch.setenv("HERMES_AUTH_VERIFY", "false")
        client = AuthClient("http://auth.test", verify=True)
        client.close()
        assert captured["verify"] is False


class TestSignChallengeErrors:
    def test_sign_without_identity_raises(self):
        from hermes_id.auth_client import AuthClient

        client = AuthClient("http://auth.test")  # no identity_dir
        try:
            with pytest.raises(RuntimeError, match="No identity"):
                client.sign_challenge("QUFBQQ==")
        finally:
            client.close()

    def test_sign_without_password(self, tmp_path, monkeypatch):
        """sign_challenge raises when no passphrase is available."""
        from hermes_id.auth_client import AuthClient
        from hermes_id.storage import IdentityStorage

        d = str(tmp_path / "identity")
        IdentityStorage(directory=d).create("secret-pass-1234")
        client = AuthClient("http://auth.test", identity_dir=d)
        monkeypatch.delenv("HERMES_ID_PASSPHRASE", raising=False)
        try:
            with pytest.raises(RuntimeError, match="HERMES_ID_PASSPHRASE"):
                client.sign_challenge("QUFBQQ==")
        finally:
            client.close()

    def test_sign_with_explicit_password(self, tmp_path):
        """sign_challenge accepts an explicit password (skips env lookup)."""
        from hermes_id.auth_client import AuthClient
        from hermes_id.storage import IdentityStorage

        d = str(tmp_path / "identity")
        IdentityStorage(directory=d).create("secret-pass-1234")
        client = AuthClient("http://auth.test", identity_dir=d)
        try:
            # Password passed explicitly → signs without touching the env.
            sig = client.sign_challenge("QUFBQQ==", password="secret-pass-1234")
            assert sig
            import base64

            base64.urlsafe_b64decode(sig + "==")
        finally:
            client.close()

    def test_get_identity_card_json_without_identity(self):
        from hermes_id.auth_client import AuthClient

        client = AuthClient("http://auth.test")
        try:
            with pytest.raises(RuntimeError, match="No identity"):
                client.get_identity_card_json()
        finally:
            client.close()


class TestContextManager:
    def test_with_statement_closes_client(self):
        """``with AuthClient(...) as client:`` auto-closes on exit."""
        from hermes_id.auth_client import AuthClient

        class FakeHTTPX:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        client = AuthClient.__new__(AuthClient)
        client._client = FakeHTTPX()
        with client as c:
            assert c is client
        assert client._client.closed is True

    def test_authflow_with_statement_closes_client(self):
        """``with AuthFlow(...) as flow:`` auto-closes on exit."""
        from hermes_id.auth_client import AuthClient, AuthFlow

        class FakeHTTPX:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        flow = AuthFlow.__new__(AuthFlow)
        flow._client = AuthClient.__new__(AuthClient)
        flow._client._client = FakeHTTPX()
        with flow as f:
            assert f is flow
        assert flow._client._client.closed is True


class TestRefreshAndList:
    def test_refresh_token_401_returns_none(self):
        """refresh_token returns None on 401 (invalid/expired token)."""
        client, _ = _make_client([(401, {"error": "Token invalid"})])
        try:
            assert client.refresh_token("expired.token") is None
        finally:
            client.close()

    def test_list_agents_with_status(self):
        """list_agents passes status through to the query string."""
        client, requests = _make_client([(200, {"agents": [], "total": 0})])
        try:
            result = client.list_agents(status="approved")
            assert result["total"] == 0
            assert requests[0].url.params["status"] == "approved"
        finally:
            client.close()

    def test_list_agents_with_project_and_search(self):
        client, requests = _make_client([(200, {"agents": [], "total": 0})])
        try:
            client.list_agents(search="foo", project="spacetime-tv", page=2, page_size=25)
            params = requests[0].url.params
            assert params["search"] == "foo"
            assert params["project"] == "spacetime-tv"
            assert params["page"] == "2"
            assert params["page_size"] == "25"
        finally:
            client.close()
