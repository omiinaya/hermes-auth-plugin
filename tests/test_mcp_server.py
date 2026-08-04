"""
Tests for the hermes-id MCP server handlers (`hermes_id.mcp_server`).

The handlers are pure JSON-string methods on HermesIDMCPServer, so they're
tested directly via object.__new__ (no MCP SDK / stdio transport needed).
Covers: status, export, verify_card, sign, verify_signature, verify_rotation,
and auth_client (register/status/verify_token/error paths).
"""

import json

import pytest

from hermes_id.mcp_server import HermesIDMCPServer


@pytest.fixture(autouse=True)
def fast_crypto(monkeypatch):
    """Force the fast PBKDF2 KDF so these tests don't pay scrypt cost."""
    import hermes_id.crypto as crypto_mod
    from hermes_id.crypto import _KDF_PBKDF2

    monkeypatch.setattr(crypto_mod, "_kdf_id", lambda: _KDF_PBKDF2)


def make_server(identity_dir):
    """Build a HermesIDMCPServer without the mcp SDK constructor."""
    from hermes_id.storage import IdentityStorage

    server = object.__new__(HermesIDMCPServer)
    server._storage = IdentityStorage(directory=identity_dir)
    return server


@pytest.fixture
def configured(tmp_path, monkeypatch):
    """A server backed by a real initialized identity."""
    from hermes_id.storage import IdentityStorage

    d = str(tmp_path / "identity")
    IdentityStorage(directory=d).create("test-pass-1234", metadata={"profile": "mcp-test"})
    monkeypatch.setenv("HERMES_ID_PASSPHRASE", "test-pass-1234")
    return make_server(d)


class TestStatus:
    def test_status_not_configured(self, tmp_path):
        srv = make_server(str(tmp_path / "empty"))
        out = json.loads(srv._handle_status())
        assert out["status"] == "not_configured"

    def test_status_ok(self, configured):
        out = json.loads(configured._handle_status())
        assert out["status"] == "ok"
        assert out["did"].startswith("did:hermes:")
        assert out["card_valid"] is True


class TestExport:
    def test_export(self, configured):
        card = json.loads(configured._handle_export())
        assert card["id"].startswith("did:hermes:")

    def test_export_not_configured(self, tmp_path):
        srv = make_server(str(tmp_path / "empty"))
        out = json.loads(srv._handle_export())
        assert "error" in out


class TestVerifyCard:
    def test_verify_valid(self, configured):
        card = json.loads(configured._handle_export())
        out = json.loads(configured._handle_verify_card({"identity_card_json": json.dumps(card)}))
        assert out["valid"] is True

    def test_verify_tampered(self, configured):
        card = json.loads(configured._handle_export())
        card["proof"]["signatureValue"] = card["proof"]["signatureValue"][:-4] + "AAAA"
        out = json.loads(configured._handle_verify_card({"identity_card_json": json.dumps(card)}))
        assert out["valid"] is False

    def test_verify_bad_json(self, configured):
        out = json.loads(configured._handle_verify_card({"identity_card_json": "not json"}))
        assert out["valid"] is False
        assert "Invalid card JSON" in out["error"]


class TestSign:
    def test_sign_roundtrip(self, configured):
        msg = "attack at dawn"
        out = json.loads(configured._handle_sign({"message_b64": __import__("base64").urlsafe_b64encode(msg.encode()).decode()}))
        assert "signature_b64" in out
        assert out["did"].startswith("did:hermes:")

    def test_sign_no_passphrase(self, tmp_path, monkeypatch):
        from hermes_id.storage import IdentityStorage

        d = str(tmp_path / "identity")
        IdentityStorage(directory=d).create("pw")
        monkeypatch.delenv("HERMES_ID_PASSPHRASE", raising=False)
        srv = make_server(d)
        out = json.loads(srv._handle_sign({"message_b64": "aGVsbG8="}))
        assert "HERMES_ID_PASSPHRASE" in out["error"]

    def test_sign_bad_base64(self, configured):
        out = json.loads(configured._handle_sign({"message_b64": "%%%" }))
        assert "Invalid base64" in out["error"]

    def test_sign_not_configured(self, tmp_path):
        srv = make_server(str(tmp_path / "empty"))
        out = json.loads(srv._handle_sign({"message_b64": "aGVsbG8="}))
        assert "No identity" in out["error"]


class TestVerifySignature:
    def test_verify_valid(self, configured):
        msg = "verify me"
        msg_b64 = __import__("base64").urlsafe_b64encode(msg.encode()).decode()
        signed = json.loads(configured._handle_sign({"message_b64": msg_b64}))
        card = json.loads(configured._handle_export())

        out = json.loads(configured._handle_verify_signature({
            "message_b64": msg_b64,
            "signature_b64": signed["signature_b64"],
            "identity_card_json": json.dumps(card),
        }))
        assert out["valid"] is True

    def test_verify_tampered_message(self, configured):
        msg = "original"
        msg_b64 = __import__("base64").urlsafe_b64encode(msg.encode()).decode()
        signed = json.loads(configured._handle_sign({"message_b64": msg_b64}))
        card = json.loads(configured._handle_export())

        tampered = __import__("base64").urlsafe_b64encode(b"tampered").decode()
        out = json.loads(configured._handle_verify_signature({
            "message_b64": tampered,
            "signature_b64": signed["signature_b64"],
            "identity_card_json": json.dumps(card),
        }))
        assert out["valid"] is False

    def test_verify_bad_base64(self, configured):
        out = json.loads(configured._handle_verify_signature({
            "message_b64": "!!!", "signature_b64": "!!!", "identity_card_json": "{}",
        }))
        assert out["valid"] is False
        assert "Invalid base64" in out["error"]


class TestVerifyRotation:
    def test_no_rotation_metadata(self, configured):
        card = json.loads(configured._handle_export())
        out = json.loads(configured._handle_verify_rotation({"identity_card_json": json.dumps(card)}))
        assert out["valid"] is False
        assert "no rotation" in out["error"]

    def test_rotated_card_valid(self, tmp_path, monkeypatch):
        from hermes_id.storage import IdentityStorage

        d = str(tmp_path / "identity")
        storage = IdentityStorage(directory=d)
        storage.create("test-pass-1234")
        rotated = storage.rotate("test-pass-1234", keep_backup=False)
        srv = make_server(d)
        card_json = rotated.to_json()
        out = json.loads(srv._handle_verify_rotation({"identity_card_json": card_json}))
        assert out["valid"] is True
        assert out["previous_did"]


class TestAuthClient:
    def test_server_url_required(self, configured):
        out = json.loads(configured._handle_auth_client({"action": "status"}))
        assert "server_url is required" in out["error"]

    def test_unknown_action(self, configured):
        out = json.loads(configured._handle_auth_client({"server_url": "http://x", "action": "nope"}))
        assert "Unknown action" in out["error"]

    def test_register(self, configured, monkeypatch):
        import hermes_id.auth_client as auth

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            def register_agent(self, did, display_name="", projects=None):
                return {"did": did, "status": "pending", "projects": projects or []}

            def close(self):
                pass

        monkeypatch.setattr(auth, "AuthClient", FakeClient)
        out = json.loads(configured._handle_auth_client({
            "server_url": "http://x", "action": "register", "projects": ["spacetime-tv"],
        }))
        assert out["status"] == "pending"
        assert out["projects"] == ["spacetime-tv"]

    def test_status_action(self, configured, monkeypatch):
        import hermes_id.auth_client as auth

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            def get_agent_status(self, did):
                return {"did": did, "status": "approved"}

            def close(self):
                pass

        monkeypatch.setattr(auth, "AuthClient", FakeClient)
        out = json.loads(configured._handle_auth_client({"server_url": "http://x", "action": "status"}))
        assert out["status"] == "approved"

    def test_verify_token_valid(self, configured, monkeypatch):
        import hermes_id.auth_client as auth

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            def verify_token(self, token):
                return {"did": "did:hermes:xyz", "aud": "spacetime-tv"}

            def close(self):
                pass

        monkeypatch.setattr(auth, "AuthClient", FakeClient)
        out = json.loads(configured._handle_auth_client({
            "server_url": "http://x", "action": "verify_token", "token": "abc",
        }))
        assert out["valid"] is True
        assert out["did"] == "did:hermes:xyz"

    def test_verify_token_invalid(self, configured, monkeypatch):
        import hermes_id.auth_client as auth

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            def verify_token(self, token):
                return None

            def close(self):
                pass

        monkeypatch.setattr(auth, "AuthClient", FakeClient)
        out = json.loads(configured._handle_auth_client({
            "server_url": "http://x", "action": "verify_token", "token": "bad",
        }))
        assert out["valid"] is False
