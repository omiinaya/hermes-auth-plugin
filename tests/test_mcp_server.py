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

    def test_verify_token_requires_token(self, configured, monkeypatch):
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
            "server_url": "http://x", "action": "verify_token",
        }))
        assert "token is required" in out["error"]

    def test_login_action(self, configured, monkeypatch):
        """login uses AuthFlow and returns a token."""
        import hermes_id.auth_client as auth

        class FakeFlow:
            def __init__(self, *a, **kw):
                pass

            def login(self, aud=None):
                return "token-123"

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            def close(self):
                pass

        monkeypatch.setattr(auth, "AuthClient", FakeClient)
        monkeypatch.setattr(auth, "AuthFlow", FakeFlow)
        out = json.loads(configured._handle_auth_client({
            "server_url": "http://x", "action": "login", "aud": "spacetime-tv",
        }))
        assert out["token"] == "token-123"
        assert out["aud"] == "spacetime-tv"

    def test_status_no_identity(self, tmp_path, monkeypatch):
        import hermes_id.auth_client as auth

        srv = make_server(str(tmp_path / "empty"))

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            def close(self):
                pass

        monkeypatch.setattr(auth, "AuthClient", FakeClient)
        out = json.loads(srv._handle_auth_client({
            "server_url": "http://x", "action": "status",
        }))
        assert "No identity configured" in out["error"]

    def test_auth_import_error(self, configured, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "hermes_id.auth_client":
                raise ImportError("httpx missing")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        out = json.loads(configured._handle_auth_client({
            "server_url": "http://x", "action": "status",
        }))
        assert "not available" in out["error"]

    def test_sign_failure(self, configured, monkeypatch):
        """A wrong passphrase yields a sign error, not a crash."""
        monkeypatch.setenv("HERMES_ID_PASSPHRASE", "wrong-passphrase")
        out = json.loads(configured._handle_sign({"message_b64": "aGVsbG8="}))
        assert "Cannot sign" in out.get("error", "")

    def test_sign_invalid_base64(self, configured):
        out = json.loads(configured._handle_sign({"message_b64": "%%%" }))
        assert "Invalid base64" in out.get("error", "")

    def test_verify_rotation_invalid_proof(self, configured):
        """A card with rotation metadata but an invalid proof is rejected."""
        from hermes_id.storage import IdentityStorage

        d = str(configured._storage._dir)
        storage = IdentityStorage(directory=d)
        card = storage.get_identity_card()
        data = json.loads(card.to_json())
        # Fake rotation metadata on an un-rotated card → proof can't verify
        data["metadata"]["rotation"] = {
            "previous_did": "did:hermes:some-other-key",
            "previous_public_key": "AAAAAAAAAAAA",
            "transition_signature": "BBBB",
            "rotated_at": "2026-08-04T00:00:00Z",
        }
        out = json.loads(configured._handle_verify_rotation(
            {"identity_card_json": json.dumps(data)}
        ))
        assert out["valid"] is False
        assert out.get("error")

    def test_verify_rotation_invalid_card_json(self, configured):
        out = json.loads(configured._handle_verify_rotation(
            {"identity_card_json": "{bad json"}
        ))
        assert out["valid"] is False
        assert "Invalid card JSON" in out["error"]

    def test_verify_signature_invalid_card_json(self, configured):
        out = json.loads(configured._handle_verify_signature({
            "message_b64": "aGVsbG8=",
            "signature_b64": "AAAA",
            "identity_card_json": "{bad json",
        }))
        assert out["valid"] is False
        assert "Invalid card JSON" in out["error"]

    def test_verify_signature_card_without_pubkey(self, configured):
        from hermes_id.storage import IdentityStorage

        d = str(configured._storage._dir)
        storage = IdentityStorage(directory=d)
        card = storage.get_identity_card()
        data = json.loads(card.to_json())
        data["verification_method"][0]["publicKeyMultibase"] = ""
        out = json.loads(configured._handle_verify_signature({
            "message_b64": "aGVsbG8=",
            "signature_b64": "AAAA",
            "identity_card_json": json.dumps(data),
        }))
        assert out["valid"] is False
        assert "No public key" in out["error"]

    def test_verify_signature_unparseable_pubkey(self, configured):
        from hermes_id.storage import IdentityStorage

        d = str(configured._storage._dir)
        storage = IdentityStorage(directory=d)
        card = storage.get_identity_card()
        data = json.loads(card.to_json())
        data["verification_method"][0]["publicKeyMultibase"] = "u%%%%"
        out = json.loads(configured._handle_verify_signature({
            "message_b64": "aGVsbG8=",
            "signature_b64": "AAAA",
            "identity_card_json": json.dumps(data),
        }))
        assert out["valid"] is False
        assert "Cannot parse key" in out["error"]

    def test_verify_signature_invalid_base64(self, configured):
        out = json.loads(configured._handle_verify_signature({
            "message_b64": "%%%",
            "signature_b64": "AAAA",
            "identity_card_json": "{}",
        }))
        assert out["valid"] is False
        assert "Invalid base64" in out["error"]

    def test_verify_signature_bad_signature(self, configured):
        from hermes_id.storage import IdentityStorage

        d = str(configured._storage._dir)
        storage = IdentityStorage(directory=d)
        card = storage.get_identity_card()
        out = json.loads(configured._handle_verify_signature({
            "message_b64": "aGVsbG8=",
            "signature_b64": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
            "identity_card_json": card.to_json(),
        }))
        assert out["valid"] is False


# ---------------------------------------------------------------------------
# register_tools — modern (mcp >= 2.0) and legacy decorator APIs
# ---------------------------------------------------------------------------


class TestRegisterToolsModern:
    """Drive the real mcp 2.0 SDK: register_tools must not crash and the
    registered handlers must answer tools/list and tools/call.

    Skipped when the installed mcp SDK predates the 2.0 API
    (``add_request_handler`` / ``get_request_handler``) — these tests
    need the real modern Server object, and the source's own
    ``_MCP_MODERN`` detection means an older SDK legitimately takes the
    legacy decorator path (covered by TestRegisterToolsLegacy)."""

    @pytest.fixture(autouse=True)
    def _require_modern_sdk(self):
        from mcp.server.lowlevel import Server as LowLevelServer

        if not (
            hasattr(LowLevelServer, "add_request_handler")
            and hasattr(LowLevelServer, "get_request_handler")
        ):
            pytest.skip(
                "mcp SDK < 2.0 installed — modern add_request_handler "
                "API not available (legacy path covered elsewhere)"
            )

    def _real_server(self, identity_dir):
        from hermes_id.mcp_server import HermesIDMCPServer

        return HermesIDMCPServer(identity_dir=identity_dir)

    def test_register_modern_succeeds(self, configured, tmp_path):


        srv = self._real_server(str(tmp_path / "real"))
        srv.register_tools()
        app = srv._app
        assert app.get_request_handler("tools/list") is not None
        assert app.get_request_handler("tools/call") is not None

    def test_modern_list_and_call_handlers(self, configured, monkeypatch):
        import asyncio

        import mcp_types


        srv = self._real_server(str(configured._storage._dir))
        srv.register_tools()
        app = srv._app
        list_entry = app.get_request_handler("tools/list")
        call_entry = app.get_request_handler("tools/call")

        async def run():
            list_params = mcp_types.PaginatedRequestParams()
            result = await list_entry.handler(None, list_params)
            tools = result["tools"] if isinstance(result, dict) else result.tools
            names = [t["name"] if isinstance(t, dict) else t.name for t in tools]
            assert "hermes_id_status" in names
            assert "hermes_id_auth_client" in names

            call_params = mcp_types.CallToolRequestParams(
                name="hermes_id_status", arguments={}
            )
            r2 = await call_entry.handler(None, call_params)
            content = r2["content"] if isinstance(r2, dict) else r2.content
            text = content[0]["text"] if isinstance(content[0], dict) else content[0].text
            assert '"status": "ok"' in text

            bad = mcp_types.CallToolRequestParams(name="nope", arguments={})
            r3 = await call_entry.handler(None, bad)
            c3 = r3["content"] if isinstance(r3, dict) else r3.content
            t3 = c3[0]["text"] if isinstance(c3[0], dict) else c3[0].text
            assert "Unknown tool" in t3

            # error path — sign without a passphrase set
            monkeypatch.delenv("HERMES_ID_PASSPHRASE", raising=False)
            sign_call = mcp_types.CallToolRequestParams(
                name="hermes_id_sign", arguments={"message_b64": "aGVsbG8="}
            )
            r4 = await call_entry.handler(None, sign_call)
            c4 = r4["content"] if isinstance(r4, dict) else r4.content
            t4 = c4[0]["text"] if isinstance(c4[0], dict) else c4[0].text
            assert "error" in t4.lower() or "unlock" in t4.lower() or "passphrase" in t4.lower()

            # exception path — a raising handler is converted to is_error

            def boom(*a, **kw):
                raise RuntimeError("kaboom")

            monkeypatch.setattr(srv, "_dispatch", boom)
            err_call = mcp_types.CallToolRequestParams(
                name="hermes_id_status", arguments={}
            )
            r5 = await call_entry.handler(None, err_call)
            c5 = r5["content"] if isinstance(r5, dict) else r5.content
            t5 = c5[0]["text"] if isinstance(c5[0], dict) else c5[0].text
            assert "Error: kaboom" in t5
            if isinstance(r5, dict):
                assert r5.get("is_error") is True

        asyncio.run(run())


class TestRegisterToolsLegacy:
    """The legacy decorator path (mcp < 2.0) must still work when the
    SDK is older. We simulate an old-style Server object and force the
    module to take the non-modern branch."""

    def test_legacy_registration(self, configured, tmp_path, monkeypatch):
        import asyncio

        import hermes_id.mcp_server as mod
        from hermes_id.mcp_server import HermesIDMCPServer

        # Force the legacy branch regardless of the installed SDK
        monkeypatch.setattr(mod, "_MCP_MODERN", False)

        class FakeApp:
            def __init__(self):
                self._list_tools = None
                self._call_tool = None

            def list_tools(self):
                def deco(fn):
                    self._list_tools = fn
                    return fn

                return deco

            def call_tool(self):
                def deco(fn):
                    self._call_tool = fn
                    return fn

                return deco

        srv = object.__new__(HermesIDMCPServer)
        srv._storage = configured._storage
        srv._app = FakeApp()
        srv.register_tools()

        assert srv._app._list_tools is not None
        assert srv._app._call_tool is not None

        # list_tools returns the 7 definitions
        async def run():
            tools = await srv._app._list_tools()
            names = [t.name for t in tools]
            assert len(names) == 7
            assert "hermes_id_status" in names
            # call_tool routes to handlers
            content = await srv._app._call_tool("hermes_id_status", {})
            assert '"status": "ok"' in content[0].text
            content2 = await srv._app._call_tool("hermes_id_export", {})
            assert "did:hermes:" in content2[0].text
            content3 = await srv._app._call_tool("hermes_id_verify_card", {
                "identity_card_json": configured._handle_export(),
            })
            assert '"valid": true' in content3[0].text
            content4 = await srv._app._call_tool("unknown_tool", {})
            assert "Unknown tool" in content4[0].text

        asyncio.run(run())

    def test_legacy_dispatch_routes_all_handlers(self, configured, monkeypatch):
        """The legacy dispatch routes every tool name to its handler."""
        import asyncio

        import hermes_id.mcp_server as mod
        from hermes_id.mcp_server import HermesIDMCPServer

        monkeypatch.setattr(mod, "_MCP_MODERN", False)

        class FakeApp:
            def __init__(self):
                self._list_tools = None
                self._call_tool = None

            def list_tools(self):
                def deco(fn):
                    self._list_tools = fn
                    return fn

                return deco

            def call_tool(self):
                def deco(fn):
                    self._call_tool = fn
                    return fn

                return deco

        srv = object.__new__(HermesIDMCPServer)
        srv._storage = configured._storage
        srv._app = FakeApp()
        srv.register_tools()

        async def run():
            # sign — needs a passphrase set by the configured fixture
            c = await srv._app._call_tool("hermes_id_sign", {"message_b64": "aGVsbG8="})
            assert '"signature_b64"' in c[0].text
            # verify_signature with a real signature
            card = configured._storage.get_identity_card()
            c2 = await srv._app._call_tool("hermes_id_verify_signature", {
                "message_b64": "aGVsbG8=",
                "signature_b64": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
                "identity_card_json": card.to_json(),
            })
            assert '"valid": false' in c2[0].text
            # verify_rotation
            c3 = await srv._app._call_tool("hermes_id_verify_rotation", {
                "identity_card_json": card.to_json(),
            })
            assert '"valid"' in c3[0].text
            # auth_client — server_url missing → error JSON, no crash
            c4 = await srv._app._call_tool("hermes_id_auth_client", {"action": "status"})
            assert "server_url is required" in c4[0].text

        asyncio.run(run())

    def test_legacy_call_tool_exception_wrapped(self, configured, monkeypatch):
        """A handler exception is converted to an Error TextContent."""
        import asyncio

        import hermes_id.mcp_server as mod
        from hermes_id.mcp_server import HermesIDMCPServer

        monkeypatch.setattr(mod, "_MCP_MODERN", False)

        class FakeApp:
            def __init__(self):
                self._list_tools = None
                self._call_tool = None

            def list_tools(self):
                def deco(fn):
                    self._list_tools = fn
                    return fn

                return deco

            def call_tool(self):
                def deco(fn):
                    self._call_tool = fn
                    return fn

                return deco

        srv = object.__new__(HermesIDMCPServer)
        srv._storage = configured._storage
        srv._app = FakeApp()
        srv.register_tools()

        def boom(*a, **kw):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(srv, "_dispatch", boom)

        async def run():
            content = await srv._app._call_tool("hermes_id_status", {})
            assert "Error: kaboom" in content[0].text

        asyncio.run(run())

    def test_legacy_dispatch_error_wrapped(self, configured, monkeypatch):
        import asyncio

        import hermes_id.mcp_server as mod
        from hermes_id.mcp_server import HermesIDMCPServer

        monkeypatch.setattr(mod, "_MCP_MODERN", False)

        class FakeApp:
            def __init__(self):
                self._list_tools = None
                self._call_tool = None

            def list_tools(self):
                def deco(fn):
                    self._list_tools = fn
                    return fn

                return deco

            def call_tool(self):
                def deco(fn):
                    self._call_tool = fn
                    return fn

                return deco

        srv = object.__new__(HermesIDMCPServer)
        srv._storage = configured._storage
        srv._app = FakeApp()
        srv.register_tools()
        # Force the handler to raise — the wrapper must convert to Error text
        async def run():
            content = await srv._app._call_tool("hermes_id_status", {})
            assert isinstance(content[0].text, str)

        asyncio.run(run())


class TestRegisterToolsModernFakeSDK:
    """Exercise the modern ``add_request_handler`` registration path with a
    FAKE modern SDK, so the branch is covered even when the installed mcp
    SDK predates 2.0 (the real-SDK test class TestRegisterToolsModern is
    skipped in that case).

    This covers _register_tools_modern: handler registration, list/call
    dispatch with mcp_types params, and the error→is_error conversion.
    """

    def test_modern_registration_with_fake_sdk(self, configured, monkeypatch):
        import asyncio

        import hermes_id.mcp_server as mod
        from hermes_id.mcp_server import HermesIDMCPServer

        # Force the modern branch regardless of the installed SDK
        monkeypatch.setattr(mod, "_MCP_MODERN", True)

        class FakeModernApp:
            def __init__(self):
                self.handlers: dict = {}

            def add_request_handler(self, method, params_type, handler):
                self.handlers[method] = (params_type, handler)

        app = FakeModernApp()
        srv = object.__new__(HermesIDMCPServer)
        srv._storage = configured._storage
        srv._app = app
        srv.register_tools()

        assert "tools/list" in app.handlers
        assert "tools/call" in app.handlers

        import mcp_types

        list_params_type, on_list = app.handlers["tools/list"]
        assert list_params_type is mcp_types.PaginatedRequestParams
        _, on_call = app.handlers["tools/call"]

        async def run():
            result = await on_list(None, mcp_types.PaginatedRequestParams())
            tools = result["tools"]
            names = [t["name"] for t in tools]
            assert len(names) == 7
            assert "hermes_id_status" in names

            r2 = await on_call(
                None,
                mcp_types.CallToolRequestParams(name="hermes_id_status", arguments={}),
            )
            assert '\"status\": \"ok\"' in r2["content"][0]["text"]

            # success path (sign with passphrase configured) — no is_error
            r3 = await on_call(
                None,
                mcp_types.CallToolRequestParams(name="hermes_id_sign", arguments={"message_b64": "aGVsbG8="}),
            )
            assert "is_error" not in r3  # success → no error flag
            assert "signature_b64" in r3["content"][0]["text"]

            # unknown tool → returned as JSON error text (no exception)
            r4 = await on_call(
                None,
                mcp_types.CallToolRequestParams(name="unknown_tool", arguments={}),
            )
            assert "is_error" not in r4
            assert "Unknown tool" in r4["content"][0]["text"]

            # dispatch exception → is_error flag set to True
        asyncio.run(run())

        def boom(*a, **kw):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(srv, "_dispatch", boom)

        async def run_error():
            r5 = await on_call(
                None,
                mcp_types.CallToolRequestParams(name="hermes_id_status", arguments={}),
            )
            assert r5["is_error"] is True
            assert "kaboom" in r5["content"][0]["text"]

        asyncio.run(run_error())


class TestModuleGuards:
    def test_main_without_mcp_sdk(self, capsys, monkeypatch):
        """main() exits cleanly with a hint when the SDK is missing."""
        import hermes_id.mcp_server as mod

        monkeypatch.setattr(mod, "HAS_MCP", False)
        with pytest.raises(SystemExit) as exc:
            mod.main()
        assert exc.value.code == 1
        assert "MCP SDK not installed" in capsys.readouterr().out

    def test_main_entrypoint(self, monkeypatch):
        """main() wires HermesIDMCPServer.run() through asyncio."""
        import hermes_id.mcp_server as mod

        calls: dict = {}

        class FakeServer:
            async def run(self):
                calls["ran"] = True

        monkeypatch.setattr(mod, "HermesIDMCPServer", lambda *a, **kw: FakeServer())
        mod.main()
        assert calls.get("ran") is True

    def test_run_wires_stdio_transport(self, monkeypatch):
        """run() registers tools and drives the stdio transport."""
        import asyncio
        from contextlib import asynccontextmanager

        import hermes_id.mcp_server as mod
        from hermes_id.mcp_server import HermesIDMCPServer

        srv = HermesIDMCPServer(identity_dir="/tmp/nonexistent-xyz")
        calls: dict = {}

        @asynccontextmanager
        async def fake_stdio():
            yield (object(), object())

        monkeypatch.setattr(mod, "stdio_server", fake_stdio)

        async def fake_run(rs, ws, opts):
            calls["ran"] = True

        srv._app.run = fake_run  # type: ignore[method-assign]
        asyncio.run(srv.run())
        assert calls.get("ran") is True

    def test_server_advertises_hermes_id_version(self, tmp_path, monkeypatch):
        """The MCP Server is constructed with hermes-id's own version so
        serverInfo reports OUR version (1.4.1...), not the mcp SDK's
        fallback. Older SDKs ignore the kwarg; modern ones advertise it."""
        import hermes_id.mcp_server as mod
        from hermes_id import __version__

        captured: dict = {}

        def fake_server(name, **kwargs):
            captured["name"] = name
            captured["kwargs"] = kwargs
            return object.__new__(mod.HermesIDMCPServer)

        monkeypatch.setattr(mod, "Server", fake_server)
        mod.HermesIDMCPServer(identity_dir="/tmp/nonexistent-xyz")
        assert captured["name"] == "hermes-id"
        assert captured["kwargs"].get("version") == __version__

    def test_module_import_error_sets_has_mcp_false(self, tmp_path):
        """When the mcp SDK can't be imported, HAS_MCP is False and the
        module still loads (guarded import)."""
        import subprocess
        import sys

        script = (
            "import sys\n"
            "class Blocker:\n"
            "    def find_module(self, name, path=None):\n"
            "        if name == 'mcp' or name.startswith('mcp.'):\n"
            "            raise ImportError('blocked for test')\n"
            "        return None\n"
            "sys.meta_path.insert(0, Blocker())\n"
            "import hermes_id.mcp_server as m\n"
            "print('HAS_MCP=', m.HAS_MCP)\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
        )
        assert "HAS_MCP= False" in result.stdout, result.stderr
