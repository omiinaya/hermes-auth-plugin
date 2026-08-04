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
