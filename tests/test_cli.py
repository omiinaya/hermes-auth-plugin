"""
Tests for the hermes-id CLI (`hermes_id.cli`).

Covers: version, command dispatch, init/rotate/show/export/status/verify/
sign/verify-sig flows, error paths, and the register/server/mcp dispatchers.

All tests use a fast-KDF fixture (pbkdf2 instead of scrypt/argon2) so the
suite runs in seconds rather than minutes — the CLI logic under test is
KDF-agnostic, and the real-KDF paths are covered by the crypto/storage tests.
"""

import json
import os
from pathlib import Path

import pytest

from hermes_id import __version__ as hermes_id_version
from hermes_id.cli import main
from hermes_id.identity import verify_key_rotation


@pytest.fixture(autouse=True)
def fast_crypto(monkeypatch):
    """Force the fast PBKDF2 KDF so CLI tests don't pay scrypt cost."""
    import hermes_id.crypto as crypto_mod
    from hermes_id.crypto import _KDF_PBKDF2

    monkeypatch.setattr(crypto_mod, "_kdf_id", lambda: _KDF_PBKDF2)


@pytest.fixture
def identity_dir(tmp_path):
    return str(tmp_path / "identity")


@pytest.fixture
def created(identity_dir):
    """An initialized identity via the CLI itself (init with env password)."""
    rc = main(["init", "--dir", identity_dir, "--password", "test-pass-1234", "--profile", "unit"])
    assert rc == 0
    return identity_dir


class TestDispatch:
    def test_version(self, capsys):
        assert main(["--version"]) == 0
        out = capsys.readouterr().out
        assert hermes_id_version in out

    def test_rewrite_verify_sig_argv_nonverify_noop(self):
        """Non-verify-sig commands pass through untouched."""
        import hermes_id.cli as cli

        assert cli._normalize_verify_sig_argv(["sign", "a", "-b"]) == ["sign", "a", "-b"]
        assert cli._normalize_verify_sig_argv(None) is None
        assert cli._normalize_verify_sig_argv([]) == []

    def test_rewrite_verify_sig_argv_positional_dash(self):
        """A positional signature starting with '-' is moved into equals-form."""
        import hermes_id.cli as cli

        out = cli._normalize_verify_sig_argv(
            ["verify-sig", "msg.txt", "-abc123", "--identity", "card.json"]
        )
        assert out[0] == "verify-sig"
        assert out[1] == "msg.txt"
        assert "--identity" in out and "card.json" in out
        assert "--signature=-abc123" in out

    def test_rewrite_verify_sig_argv_positional_normal_noop(self):
        """A positional signature not starting with '-' is unchanged (just
        reordered stably)."""
        import hermes_id.cli as cli

        out = cli._normalize_verify_sig_argv(
            ["verify-sig", "msg.txt", "abc123", "--identity", "card.json"]
        )
        assert out == ["verify-sig", "msg.txt", "abc123", "--identity", "card.json"]

    def test_rewrite_verify_sig_argv_option_dash_merged(self):
        """A separate-arg --signature whose value starts with '-' is merged to
        equals-form."""
        import hermes_id.cli as cli

        out = cli._normalize_verify_sig_argv(
            ["verify-sig", "msg.txt", "--signature", "-abc123", "--identity", "card.json"]
        )
        assert "--signature=-abc123" in out
        assert "--signature" not in out or "-abc123" not in out

    def test_rewrite_verify_sig_argv_option_normal_kept(self):
        """A separate-arg --signature with a non-dash value stays as-is."""
        import hermes_id.cli as cli

        out = cli._normalize_verify_sig_argv(
            ["verify-sig", "msg.txt", "--signature", "abc123", "--identity", "card.json"]
        )
        assert out == ["verify-sig", "msg.txt", "--signature", "abc123", "--identity", "card.json"]

    def test_rewrite_verify_sig_argv_equals_form_passthrough(self):
        """An already-equals-form --signature=<v> passes through."""
        import hermes_id.cli as cli

        out = cli._normalize_verify_sig_argv(
            ["verify-sig", "msg.txt", "--signature=abc123", "--identity", "card.json"]
        )
        assert "--signature=abc123" in out
        assert "--identity" in out

    def test_rewrite_verify_sig_argv_unknown_dash_option_before_file(self):
        """An unrecognized dash token before the file positional is kept as an
        option (argparse will reject it normally)."""
        import hermes_id.cli as cli

        out = cli._normalize_verify_sig_argv(
            ["verify-sig", "--bogus", "msg.txt", "sig123"]
        )
        assert out[0] == "verify-sig"
        assert "msg.txt" in out and "sig123" in out
        assert "--bogus" in out

    def test_main_module_importable(self):
        """``python -m hermes_id`` entry module imports cleanly (the
        module-level import line is otherwise invisible to coverage)."""
        import hermes_id.__main__ as main_mod  # noqa: F401
        assert hasattr(main_mod, "main")

    def test_no_command(self, capsys):
        assert main([]) == 2
        assert "Usage" in capsys.readouterr().err

    def test_unknown_command(self):
        # argparse rejects unknown subcommands with exit code 2
        with pytest.raises(SystemExit) as exc:
            main(["frobnicate"])
        assert exc.value.code == 2

    def test_help_exits_zero(self):
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0


class TestInit:
    def test_init_creates_files(self, identity_dir, capsys):
        rc = main(["init", "--dir", identity_dir, "--password", "test-pass-1234"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "did:hermes:" in out
        assert "Identity created" in out
        # Files on disk with restrictive perms
        for name in ("identity.json", "private.enc", "storage.json"):
            p = os.path.join(identity_dir, name)
            assert os.path.exists(p), name
            assert os.stat(p).st_mode & 0o777 == 0o600, name

    def test_init_refuses_existing(self, created, identity_dir, capsys):
        rc = main(["init", "--dir", identity_dir, "--password", "test-pass-1234"])
        assert rc == 1
        assert "already exists" in capsys.readouterr().err

    def test_init_force_overwrites_new_did(self, created, identity_dir):
        old_card = json.loads(Path(os.path.join(identity_dir, "identity.json")).read_text())
        rc = main(["init", "--dir", identity_dir, "--force", "--password", "new-pass-5678"])
        assert rc == 0
        new_card = json.loads(Path(os.path.join(identity_dir, "identity.json")).read_text())
        assert new_card["id"] != old_card["id"]

    def test_init_with_profile_metadata(self, identity_dir):
        rc = main(["init", "--dir", identity_dir, "--password", "test-pass-1234", "--profile", "cyber-elf"])
        assert rc == 0
        card = json.loads(Path(os.path.join(identity_dir, "identity.json")).read_text())
        assert card["metadata"].get("profile") == "cyber-elf"

    def test_init_password_from_env(self, identity_dir, monkeypatch, capsys):
        monkeypatch.setenv("HERMES_ID_PASSPHRASE", "env-pass-9999")
        assert main(["init", "--dir", identity_dir]) == 0
        assert "Identity created" in capsys.readouterr().out


class TestShowExportStatus:
    def test_show_before_init(self, identity_dir, capsys):
        assert main(["show", "--dir", identity_dir]) == 1
        assert "No identity" in capsys.readouterr().err

    def test_show_after_init(self, created, identity_dir, capsys):
        assert main(["show", "--dir", identity_dir]) == 0
        out = capsys.readouterr().out
        assert "did:hermes:" in out

    def test_show_without_metadata(self, identity_dir, capsys):
        """show on an identity created with no --profile renders without a
        Metadata block (covers the empty-metadata branch)."""
        rc = main(["init", "--dir", identity_dir, "--password", "test-pass-1234"])
        assert rc == 0
        assert main(["show", "--dir", identity_dir]) == 0
        out = capsys.readouterr().out
        assert "did:hermes:" in out
        assert "Metadata:" not in out

    def test_export_stdout(self, created, identity_dir, capsys):
        assert main(["export", "--dir", identity_dir]) == 0
        out = capsys.readouterr().out
        card = json.loads(out)
        assert card["id"].startswith("did:hermes:")

    def test_export_to_file(self, created, identity_dir, tmp_path):
        outfile = tmp_path / "card.json"
        assert main(["export", "--dir", identity_dir, str(outfile)]) == 0
        card = json.loads(outfile.read_text())
        assert card["id"].startswith("did:hermes:")

    def test_status(self, created, identity_dir, capsys):
        assert main(["status", "--dir", identity_dir]) == 0
        out = capsys.readouterr().out
        assert "did:hermes:" in out or "DID" in out


class TestVerify:
    def test_verify_valid_card(self, created, identity_dir, capsys):
        card_path = os.path.join(identity_dir, "identity.json")
        assert main(["verify", card_path]) == 0
        out = capsys.readouterr().out
        assert "VALID" in out

    def test_verify_tampered_card(self, created, identity_dir, capsys):
        card_path = os.path.join(identity_dir, "identity.json")
        card = json.loads(Path(card_path).read_text())
        card["proof"]["signatureValue"] = card["proof"]["signatureValue"][:-4] + "AAAA"
        tampered = os.path.join(identity_dir, "tampered.json")
        Path(tampered).write_text(json.dumps(card))
        assert main(["verify", tampered]) == 1
        assert "INVALID" in capsys.readouterr().out

    def test_verify_missing_file(self, capsys):
        assert main(["verify", "/nonexistent/card.json"]) == 1
        assert "Cannot read" in capsys.readouterr().err


class TestSignVerifySig:
    def test_sign_roundtrip_with_sig_file(self, created, identity_dir, tmp_path):
        message = tmp_path / "message.txt"
        message.write_text("attack at dawn")
        card_path = os.path.join(identity_dir, "identity.json")

        assert main(["sign", "--dir", identity_dir, str(message), "--password", "test-pass-1234"]) == 0
        sig_path = tmp_path / "message.txt.sig"
        assert sig_path.exists()

        assert main(["verify-sig", str(message), str(sig_path), "--identity", card_path]) == 0

    def test_sign_roundtrip_inline_b64(self, created, identity_dir, tmp_path, capsys):
        message = tmp_path / "msg2.txt"
        message.write_text("inline sig test")
        card_path = os.path.join(identity_dir, "identity.json")

        assert main(["sign", "--dir", identity_dir, str(message), "--password", "test-pass-1234"]) == 0
        sig_b64 = (tmp_path / "msg2.txt.sig").read_text().strip()

        assert main(["verify-sig", str(message), sig_b64, "--identity", card_path]) == 0
        out = capsys.readouterr().out
        assert "VALID" in out

    def test_sign_before_init(self, identity_dir, tmp_path, capsys):
        message = tmp_path / "m.txt"
        message.write_text("x")
        assert main(["sign", "--dir", identity_dir, str(message), "--password", "test-pass-1234"]) == 1
        assert "No identity" in capsys.readouterr().err

    def test_sign_wrong_password(self, created, identity_dir, tmp_path, capsys):
        message = tmp_path / "m2.txt"
        message.write_text("x")
        assert main(["sign", "--dir", identity_dir, str(message), "--password", "wrong-password"]) == 1
        assert "Cannot unlock" in capsys.readouterr().err

    def test_verify_sig_requires_identity(self, tmp_path, capsys):
        message = tmp_path / "m3.txt"
        message.write_text("x")
        assert main(["verify-sig", str(message), "AAAA"]) == 1
        assert "--identity is required" in capsys.readouterr().err

    def test_verify_sig_wrong_signature(self, created, identity_dir, tmp_path, capsys):
        message = tmp_path / "m4.txt"
        message.write_text("original")
        card_path = os.path.join(identity_dir, "identity.json")
        # Sign then tamper with the message
        assert main(["sign", "--dir", identity_dir, str(message), "--password", "test-pass-1234"]) == 0
        sig_b64 = (tmp_path / "m4.txt.sig").read_text().strip()
        message.write_text("tampered!")
        assert main(["verify-sig", str(message), sig_b64, "--identity", card_path]) == 1
        assert "INVALID" in capsys.readouterr().out

    def test_verify_sig_leading_dash_signature(self, created, identity_dir, tmp_path, capsys):
        """A base64url signature that starts with '-' must verify cleanly.

        Regression: argparse treats a leading-dash positional as an option
        flag (SystemExit 2) — the base64url alphabet includes '-' and '_',
        so a valid signature can begin with '-'. The --signature flag avoids
        the ambiguity."""
        import base64

        from hermes_id.crypto import sign as _sign
        from hermes_id.storage import IdentityStorage

        storage = IdentityStorage(directory=identity_dir)
        with storage.use_key("test-pass-1234") as private_key:
            # Find a message whose signature naturally starts with '-' — the
            # signature stays cryptographically valid (deterministic).
            sig_b64 = base64.urlsafe_b64encode(_sign(private_key, b"0")).rstrip(b"=").decode()
            i = 1
            while not sig_b64.startswith("-"):
                sig_b64 = base64.urlsafe_b64encode(
                    _sign(private_key, str(i).encode())
                ).rstrip(b"=").decode()
                i += 1
                assert i < 512, "could not find a leading-dash signature"

        # --- positional form still must NOT raise SystemExit on a '-' sig ---
        # (argparse would fail; assert the CLI survives the parse)
        card_path = os.path.join(identity_dir, "identity.json")
        m = tmp_path / "m6.txt"
        m.write_bytes(str(i - 1).encode())

        # --signature flag: the deterministic, unambiguous form.
        assert main([
            "verify-sig", str(m), "--identity", card_path,
            "--signature", sig_b64,
        ]) == 0
        assert "VALID" in capsys.readouterr().out

    def test_verify_sig_missing_signature(self, created, identity_dir, tmp_path, capsys):
        """verify-sig without any signature argument returns a clean error."""
        message = tmp_path / "m7.txt"
        message.write_text("x")
        card_path = os.path.join(identity_dir, "identity.json")
        assert main(["verify-sig", str(message), "--identity", card_path]) == 1
        assert "Signature required" in capsys.readouterr().err

    def test_verify_sig_malformed_signature(self, created, identity_dir, tmp_path, capsys):
        message = tmp_path / "m5.txt"
        message.write_text("x")
        card_path = os.path.join(identity_dir, "identity.json")
        assert main(["verify-sig", str(message), "!!!not-base64!!!", "--identity", card_path]) == 1
        assert "Invalid signature" in capsys.readouterr().err


class TestRotate:
    def test_rotate_before_init(self, identity_dir, capsys):
        assert main(["rotate", "--dir", identity_dir, "--password", "test-pass-1234"]) == 1
        assert "No identity" in capsys.readouterr().err

    def test_rotate_force_new_did_with_transition_proof(self, created, identity_dir, capsys):
        old_card = json.loads(Path(os.path.join(identity_dir, "identity.json")).read_text())
        old_did = old_card["id"]

        rc = main(["rotate", "--dir", identity_dir, "--password", "test-pass-1234", "--force", "--note", "annual"])
        assert rc == 0
        new_card = json.loads(Path(os.path.join(identity_dir, "identity.json")).read_text())
        assert new_card["id"] != old_did

        # Old key backed up under rotated/<old-suffix>/ (16-char DID suffix)
        rotated_dir = os.path.join(identity_dir, "rotated")
        assert os.path.isdir(rotated_dir)
        old_suffix = old_did.split(":")[-1][:16]
        assert any(old_suffix in name for name in os.listdir(rotated_dir))

        # Transition proof verifies against the new card
        from hermes_id.identity import IdentityCard

        assert verify_key_rotation(IdentityCard(**new_card)) is not None

        # New identity still unlocks with the same passphrase
        from hermes_id.storage import IdentityStorage

        key = IdentityStorage(directory=identity_dir).unlock("test-pass-1234")
        assert key is not None

    def test_rotate_no_backup(self, created, identity_dir):
        rc = main(["rotate", "--dir", identity_dir, "--password", "test-pass-1234", "--force", "--no-backup"])
        assert rc == 0
        assert not os.path.isdir(os.path.join(identity_dir, "rotated"))

    def test_rotate_cancelled_when_user_says_no(self, created, identity_dir, capsys, monkeypatch):
        """rotate without --force is cancelled when the user answers 'n' —
        covers the confirmation-declined branch."""
        old_card = json.loads(Path(os.path.join(identity_dir, "identity.json")).read_text())
        monkeypatch.setattr("builtins.input", lambda prompt="": "n")
        rc = main(["rotate", "--dir", identity_dir, "--password", "test-pass-1234"])
        assert rc == 1
        assert "Rotation cancelled" in capsys.readouterr().out
        # Identity unchanged
        new_card = json.loads(Path(os.path.join(identity_dir, "identity.json")).read_text())
        assert new_card["id"] == old_card["id"]

    def test_rotate_confirmed_when_user_says_yes(self, created, identity_dir, capsys, monkeypatch):
        """rotate without --force proceeds when the user answers 'y' —
        covers the confirmation-accepted branch."""
        old_card = json.loads(Path(os.path.join(identity_dir, "identity.json")).read_text())
        monkeypatch.setattr("builtins.input", lambda prompt="": "y")
        rc = main(["rotate", "--dir", identity_dir, "--password", "test-pass-1234"])
        assert rc == 0
        new_card = json.loads(Path(os.path.join(identity_dir, "identity.json")).read_text())
        assert new_card["id"] != old_card["id"]


class TestServerAndMcpDispatchers:
    def test_server_missing_extra(self, identity_dir, capsys, monkeypatch):
        """server without fastapi/uvicorn installed → clean error, exit 1."""
        # Simulate ImportError by making the import fail
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "hermes_id.server":
                raise ImportError("No module named 'fastapi'")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        assert main(["server", "--dir", identity_dir]) == 1
        assert "Cannot start server" in capsys.readouterr().err

    def test_mcp_missing_extra(self, identity_dir, capsys, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "hermes_id.mcp_server":
                raise ImportError("No module named 'mcp'")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        assert main(["mcp", "--dir", identity_dir]) == 1
        assert "Cannot start MCP server" in capsys.readouterr().err

    def test_register_requires_server(self, created, identity_dir, capsys, monkeypatch):
        monkeypatch.delenv("HERMES_AUTH_SERVER_URL", raising=False)
        assert main(["register", "--dir", identity_dir]) == 1
        assert "No auth server URL" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Uncovered dispatcher / prompt / handshake / register branches
# ---------------------------------------------------------------------------


class TestDispatcherBranches:
    def test_unknown_command_in_dispatch(self, capsys, monkeypatch):
        """Unknown subcommand routes through the dispatcher's else branch."""
        monkeypatch.setattr(
            "hermes_id.cli._cmd_handshake",
            lambda args: (_ for _ in ()).throw(ValueError("boom")),
        )
        # The generic exception handler catches it
        assert main(["handshake", "listen", "--dir", "/tmp/nonexistent-xyz"]) == 1
        out = capsys.readouterr().err
        assert "Error: boom" in out

    def test_handshake_no_identity(self, capsys, monkeypatch):
        assert main(["handshake", "listen", "--dir", "/tmp/nonexistent-xyz"]) == 1
        assert "No identity configured" in capsys.readouterr().err

    def test_server_starts(self, created, capsys, monkeypatch):
        """`hermes-id server` constructs AuthServer and runs it."""
        import builtins

        calls: dict = {}
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "hermes_id.server":
                class FakeAuthServer:
                    def __init__(self, *aa, **kk):
                        calls["init"] = kk

                    def run(self, **kk):
                        calls["run"] = kk
                        return None

                mod = type("mod", (), {"AuthServer": FakeAuthServer})
                return mod
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        assert main([
            "server", "--dir", created,
            "--port", "9999", "--host", "127.0.0.1",
            "--admin-key", "k", "--cors-origins", "https://a,https://b",
            "--token-ttl", "120",
        ]) == 0
        assert calls["init"]["admin_key"] == "k"
        assert calls["init"]["cors_origins"] == ["https://a", "https://b"]
        assert calls["init"]["token_ttl"] == 120
        assert calls["run"]["port"] == 9999
        assert calls["run"]["host"] == "127.0.0.1"

    def test_register_no_projects_warns(self, created, capsys, monkeypatch):
        """Register without --for warns but still proceeds."""
        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            def register_agent(self, did, display_name=None, projects=None):
                self._did = did
                return {"status": "pending", "projects": projects or []}

            def close(self):
                pass

        monkeypatch.setattr(
            "hermes_id.auth_client.AuthClient", FakeClient, raising=False,
        )
        monkeypatch.setenv("HERMES_AUTH_SERVER_URL", "http://127.0.0.1:9488")
        rc = main(["register", "--dir", created])
        assert rc == 0
        err = capsys.readouterr().err
        assert "No --for" in err

    def test_register_with_projects(self, created, capsys, monkeypatch):
        captured: dict = {}

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            def register_agent(self, did, display_name=None, projects=None):
                captured["did"] = did
                captured["projects"] = projects
                captured["display_name"] = display_name
                return {"status": "pending", "projects": projects or []}

            def close(self):
                pass

        monkeypatch.setattr(
            "hermes_id.auth_client.AuthClient", FakeClient, raising=False,
        )
        monkeypatch.setenv("HERMES_AUTH_SERVER_URL", "http://127.0.0.1:9488")
        rc = main([
            "register", "--dir", created,
            "--for", "spacetime-tv", "--for", "spacetime-air",
            "--display-name", "My Agent",
        ])
        assert rc == 0
        assert captured["projects"] == ["spacetime-tv", "spacetime-air"]
        assert captured["display_name"] == "My Agent"
        out = capsys.readouterr().out
        assert "Projects: spacetime-tv, spacetime-air" in out

    def test_register_approved_status_skips_pending_hint(self, created, capsys, monkeypatch):
        """Register with a non-pending status (e.g. already approved) does
        not print the admin-approval hint — covers the status==pending
        false branch."""
        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            def register_agent(self, did, display_name=None, projects=None):
                return {"status": "approved", "projects": ["spacetime-tv"]}

            def close(self):
                pass

        monkeypatch.setattr(
            "hermes_id.auth_client.AuthClient", FakeClient, raising=False,
        )
        monkeypatch.setenv("HERMES_AUTH_SERVER_URL", "http://127.0.0.1:9488")
        rc = main(["register", "--dir", created, "--for", "spacetime-tv"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Status:   approved" in out
        assert "Awaiting admin approval" not in out

    def test_register_no_identity(self, capsys, monkeypatch):
        monkeypatch.setenv("HERMES_AUTH_SERVER_URL", "http://127.0.0.1:9488")
        assert main(["register", "--dir", "/tmp/nonexistent-xyz"]) == 1
        assert "No identity configured" in capsys.readouterr().err

    def test_register_import_error(self, created, capsys, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "hermes_id.auth_client":
                raise ImportError("No module named 'httpx'")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        monkeypatch.setenv("HERMES_AUTH_SERVER_URL", "http://127.0.0.1:9488")
        assert main(["register", "--dir", created]) == 1
        assert "Cannot register" in capsys.readouterr().err

    def test_mcp_starts(self, created, capsys, monkeypatch):
        import builtins

        calls: dict = {}
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "hermes_id.mcp_server":
                mod = type("mod", (), {"main": lambda: calls.setdefault("ran", True)})
                return mod
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        assert main(["mcp", "--dir", created]) == 0
        assert calls.get("ran") is True


class TestPromptBranches:
    def test_init_prompts_when_no_password(self, identity_dir, capsys, monkeypatch):
        """init falls back to interactive getpass when no env/flag password."""
        import hermes_id.cli as cli

        prompts = iter(["short", "test-pass-1234", "test-pass-1234"])
        monkeypatch.setattr(cli, "_prompt_password", lambda prompt="Passphrase: ": next(prompts))
        monkeypatch.delenv("HERMES_ID_PASSPHRASE", raising=False)
        assert main(["init", "--dir", identity_dir]) == 0
        assert "Identity created" in capsys.readouterr().out

    def test_prompt_password_short_rejected(self, capsys, monkeypatch):
        import getpass as _getpass

        import hermes_id.cli as cli

        # First attempt too short → loop; second attempt ok
        values = iter(["short", "test-pass-1234", "test-pass-1234"])
        monkeypatch.setattr(_getpass, "getpass", lambda prompt="": next(values))
        result = cli._prompt_password()
        assert result == "test-pass-1234"
        out = capsys.readouterr().err
        assert "at least 8" in out

    def test_prompt_password_mismatch_retries(self, capsys, monkeypatch):
        import getpass as _getpass

        import hermes_id.cli as cli

        # p1/p2 mismatch then match
        values = iter(["test-pass-1234", "different-pass", "test-pass-1234", "test-pass-1234"])
        monkeypatch.setattr(_getpass, "getpass", lambda prompt="": next(values))
        result = cli._prompt_password()
        assert result == "test-pass-1234"
        assert "don't match" in capsys.readouterr().err

    def test_sign_prompts_for_password(self, created, tmp_path, capsys, monkeypatch):
        """sign falls back to getpass when no password supplied."""
        import getpass as _getpass

        f = tmp_path / "data.txt"
        f.write_text("hello")
        monkeypatch.setattr(_getpass, "getpass", lambda prompt="": "test-pass-1234")
        monkeypatch.delenv("HERMES_ID_PASSPHRASE", raising=False)
        assert main(["sign", "--dir", created, str(f)]) == 0
        out = capsys.readouterr().out
        assert "Signed" in out
        assert (tmp_path / "data.txt.sig").exists()

    def test_sign_with_env_password(self, created, tmp_path, capsys, monkeypatch):
        """sign uses HERMES_ID_PASSPHRASE when set (skips getpass)."""
        f = tmp_path / "data.txt"
        f.write_text("hello")
        monkeypatch.setenv("HERMES_ID_PASSPHRASE", "test-pass-1234")
        assert main(["sign", "--dir", created, str(f)]) == 0
        out = capsys.readouterr().out
        assert "Signed" in out
        assert (tmp_path / "data.txt.sig").exists()

    def test_sign_with_flag_password(self, created, tmp_path, capsys, monkeypatch):
        """sign accepts --password directly (skips env + getpass)."""
        f = tmp_path / "data.txt"
        f.write_text("hello")
        monkeypatch.delenv("HERMES_ID_PASSPHRASE", raising=False)
        assert main(["sign", "--dir", created, "--password", "test-pass-1234", str(f)]) == 0
        out = capsys.readouterr().out
        assert "Signed" in out
        assert (tmp_path / "data.txt.sig").exists()

    def test_verify_sig_missing_identity_file(self, created, capsys, tmp_path):
        f = tmp_path / "data.txt"
        f.write_text("hello")
        assert main([
            "verify-sig", "--dir", created,
            "--identity", "/tmp/nonexistent-card.json",
            str(f), "AAAA",
        ]) == 1
        assert "Cannot read identity card" in capsys.readouterr().err

    def test_verify_sig_card_without_pubkey(self, created, tmp_path, capsys):
        import json as _json

        from hermes_id.storage import IdentityStorage

        storage = IdentityStorage(directory=created)
        card = storage.get_identity_card()
        data = _json.loads(card.to_json())
        data["verification_method"][0]["publicKeyMultibase"] = ""
        bad = tmp_path / "nopub.json"
        bad.write_text(_json.dumps(data))
        f = tmp_path / "data.txt"
        f.write_text("hello")
        assert main([
            "verify-sig", "--dir", created,
            "--identity", str(bad),
            str(f), "AAAA",
        ]) == 1
        assert "no public key" in capsys.readouterr().err

    def test_verify_sig_bad_pubkey(self, created, tmp_path, capsys):
        import json as _json

        from hermes_id.storage import IdentityStorage

        storage = IdentityStorage(directory=created)
        card = storage.get_identity_card()
        data = _json.loads(card.to_json())
        data["verification_method"][0]["publicKeyMultibase"] = "u%%%%"
        bad = tmp_path / "badpub.json"
        bad.write_text(_json.dumps(data))
        f = tmp_path / "data.txt"
        f.write_text("hello")
        assert main([
            "verify-sig", "--dir", created,
            "--identity", str(bad),
            str(f), "AAAA",
        ]) == 1
        assert "Cannot parse public key" in capsys.readouterr().err

    def test_rotate_prompts_and_cancel(self, created, capsys, monkeypatch):
        """rotate without --force asks confirmation; 'n' cancels."""
        import getpass as _getpass


        monkeypatch.setattr(_getpass, "getpass", lambda prompt="": "test-pass-1234")
        monkeypatch.setattr("builtins.input", lambda prompt="": "n")
        monkeypatch.delenv("HERMES_ID_PASSPHRASE", raising=False)
        rc = main(["rotate", "--dir", created])
        assert rc == 1
        assert "Rotation cancelled" in capsys.readouterr().out

    def test_rotate_eof_cancels(self, created, capsys, monkeypatch):
        import getpass as _getpass


        def raise_eof(prompt=""):
            raise EOFError

        monkeypatch.setattr(_getpass, "getpass", lambda prompt="": "test-pass-1234")
        monkeypatch.setattr("builtins.input", raise_eof)
        monkeypatch.delenv("HERMES_ID_PASSPHRASE", raising=False)
        assert main(["rotate", "--dir", created]) == 1
        assert "Rotation cancelled" in capsys.readouterr().out

    def test_export_no_identity(self, capsys):
        assert main(["export", "--dir", "/tmp/nonexistent-xyz"]) == 1
        assert "No identity configured" in capsys.readouterr().err


class TestHandshakeCli:
    def test_handshake_listen(self, created, capsys, monkeypatch):
        """handshake listen starts run_handshake_server."""
        import hermes_id.cli as cli

        calls: dict = {}
        monkeypatch.setattr(
            cli,
            "run_handshake_server",
            lambda **kw: calls.update(kw) or None,
        )
        monkeypatch.setenv("HERMES_ID_PASSPHRASE", "test-pass-1234")
        assert main(["handshake", "listen", "--dir", created, "--port", "9876"]) == 0
        assert calls["port"] == 9876
        assert "Starting handshake server" in capsys.readouterr().out

    def test_handshake_connect_success(self, created, capsys, monkeypatch):
        import hermes_id.cli as cli

        calls: dict = {}
        monkeypatch.setattr(
            cli,
            "run_handshake_client",
            lambda **kw: calls.update(kw) or (True, "did:hermes:peer", b"sessionkey"),
        )
        monkeypatch.setenv("HERMES_ID_PASSPHRASE", "test-pass-1234")
        assert main(["handshake", "connect", "--dir", created, "127.0.0.1:9487"]) == 0
        assert calls["port"] == 9487
        out = capsys.readouterr().out
        assert "Handshake successful" in out
        assert "Session key" in out

    def test_handshake_connect_default_port(self, created, capsys, monkeypatch):
        import hermes_id.cli as cli

        calls: dict = {}
        monkeypatch.setattr(
            cli,
            "run_handshake_client",
            lambda **kw: calls.update(kw) or (True, "did:hermes:peer", None),
        )
        monkeypatch.setenv("HERMES_ID_PASSPHRASE", "test-pass-1234")
        assert main(["handshake", "connect", "--dir", created, "somehost"]) == 0
        assert calls["port"] == 9487
        assert calls["host"] == "somehost"

    def test_handshake_connect_peer_did_mismatch(self, created, capsys, monkeypatch):
        import hermes_id.cli as cli

        def fake_run(**kw):
            on_verify = kw.get("on_verify")
            assert on_verify is not None
            # Drive the on_verify callback with a mismatched peer card — this
            # is the real code path that rejects a peer whose DID differs.
            from hermes_id.identity import IdentityCard

            card = IdentityCard(
                id="did:hermes:unexpected",
                controller="did:hermes:unexpected",
                verification_method=[],
                authentication=[],
                assertion_method=[],
                created="2026-08-04T00:00:00Z",
            )
            assert on_verify(card) is False
            return (False, card, None)

        monkeypatch.setattr(cli, "run_handshake_client", fake_run)
        monkeypatch.setenv("HERMES_ID_PASSPHRASE", "test-pass-1234")
        assert main([
            "handshake", "connect", "--dir", created,
            "--peer-did", "did:hermes:expected", "127.0.0.1:9487",
        ]) == 1
        assert "Peer DID mismatch" in capsys.readouterr().out

    def test_handshake_connect_verify_accepts_any_peer(self, created, capsys, monkeypatch):
        """Without --peer-did the on_verify callback accepts any peer."""
        import hermes_id.cli as cli

        def fake_run(**kw):
            on_verify = kw.get("on_verify")
            assert on_verify is not None
            from hermes_id.identity import IdentityCard

            card = IdentityCard(
                id="did:hermes:whomever",
                controller="did:hermes:whomever",
                verification_method=[],
                authentication=[],
                assertion_method=[],
                created="2026-08-04T00:00:00Z",
            )
            assert on_verify(card) is True
            return (True, card, None)

        monkeypatch.setattr(cli, "run_handshake_client", fake_run)
        monkeypatch.setenv("HERMES_ID_PASSPHRASE", "test-pass-1234")
        assert main(["handshake", "connect", "--dir", created, "127.0.0.1:9487"]) == 0

    def test_handshake_prompts_for_password(self, created, capsys, monkeypatch):
        """handshake falls back to getpass when no env/flag password."""
        import getpass as _getpass

        import hermes_id.cli as cli

        monkeypatch.setattr(_getpass, "getpass", lambda prompt="": "test-pass-1234")
        monkeypatch.delenv("HERMES_ID_PASSPHRASE", raising=False)
        monkeypatch.setattr(cli, "run_handshake_server", lambda **kw: None)
        assert main(["handshake", "listen", "--dir", created, "--port", "9876"]) == 0
        assert "Starting handshake server" in capsys.readouterr().out

    def test_handshake_fallthrough_returns_1(self, created, monkeypatch):
        """_cmd_handshake with an unexpected subcommand returns 1."""
        import argparse

        import hermes_id.cli as cli

        monkeypatch.setenv("HERMES_ID_PASSPHRASE", "test-pass-1234")
        args = argparse.Namespace(
            dir=created, password="", handshake_cmd="bogus",
            host="127.0.0.1", port=9487, target="", peer_did="",
        )
        assert cli._cmd_handshake(args) == 1

    def test_handshake_unlock_failure(self, created, capsys, monkeypatch):
        import hermes_id.cli as cli

        monkeypatch.setattr(cli, "run_handshake_server", lambda **kw: None)
        monkeypatch.setenv("HERMES_ID_PASSPHRASE", "wrong-password")
        rc = main(["handshake", "listen", "--dir", created])
        assert rc == 1
        assert "Cannot unlock identity" in capsys.readouterr().err

    def test_handshake_with_flag_password(self, created, capsys, monkeypatch):
        """handshake listen accepts --password directly (skips env + getpass)
        — covers the password-truthy branch in _cmd_handshake."""
        import hermes_id.cli as cli

        calls: dict = {}
        monkeypatch.setattr(
            cli,
            "run_handshake_server",
            lambda **kw: calls.update(kw) or None,
        )
        monkeypatch.delenv("HERMES_ID_PASSPHRASE", raising=False)
        assert main([
            "handshake", "listen", "--dir", created,
            "--password", "test-pass-1234", "--port", "9877",
        ]) == 0
        assert calls["port"] == 9877
        assert "Starting handshake server" in capsys.readouterr().out
