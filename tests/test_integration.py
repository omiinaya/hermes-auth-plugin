"""
End-to-end integration tests for the hermes-id CLI.

Tests the actual CLI binary via subprocess, covering:
- init, show, status, export, verify
- sign and verify-sig
- Full TCP handshake
- Error cases and edge conditions
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from hermes_id.crypto import _b64, _unb64
from hermes_id.identity import IdentityCard, verify_identity_card


# Find the CLI binary
def _find_cli() -> str:
    """Locate the hermes-id CLI."""
    cli = os.environ.get("HERMES_ID_CLI", "")
    if cli:
        return cli
    # Check PATH
    import shutil
    exe = shutil.which("hermes-id")
    if exe:
        return exe
    # Dev-mode fallback
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "src", "hermes_id", "cli.py",
    )


CLI = _find_cli()


def _run(*args: str, input_text: str = "") -> subprocess.CompletedProcess:
    """Run hermes-id CLI and return result."""
    cmd = [sys.executable, CLI] if CLI.endswith(".py") else [CLI]
    cmd.extend(args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
        input=input_text,
        env={**os.environ, "HERMES_HOME": os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes"))},
    )


# ---------------------------------------------------------------------------
# Test setup
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_env():
    """Create a temporary directory with its own identity config."""
    with tempfile.TemporaryDirectory() as d:
        original = os.environ.get("HERMES_HOME", "")
        hermes_home = os.path.join(d, "hermes")
        os.environ["HERMES_HOME"] = hermes_home
        os.makedirs(hermes_home, exist_ok=True)
        yield d
        if original:
            os.environ["HERMES_HOME"] = original
        else:
            os.environ.pop("HERMES_HOME", None)


@pytest.fixture
def identity_dir(isolated_env):
    """Create a temp directory for identity storage."""
    d = os.path.join(isolated_env, "identity")
    os.makedirs(d, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

class TestCLIIntegration:
    """Full CLI workflow tests."""

    def test_01_init_and_status(self, identity_dir):
        """Initialize identity and check status."""
        password = "super-secure-password-1234!"
        result = _run("init", "--dir", identity_dir, input_text=f"{password}\n{password}\n")
        print(result.stdout, result.stderr)
        assert result.returncode == 0
        assert "Identity created" in result.stdout
        assert "did:hermes:" in result.stdout
        assert "VALID" in result.stdout

        # Status
        result = _run("status", "--dir", identity_dir)
        assert result.returncode == 0
        assert "did:hermes:" in result.stdout
        assert "Ed25519" in result.stdout
        assert "AES-256-GCM" in result.stdout

    def test_02_show_and_export(self, identity_dir):
        """Show identity card and export as JSON."""
        password = "another-strong-password!"
        _run("init", "--dir", identity_dir, input_text=f"{password}\n{password}\n")
        assert Path(identity_dir, "identity.json").exists()

        # Show
        result = _run("show", "--dir", identity_dir)
        assert result.returncode == 0
        assert "did:hermes:" in result.stdout

        # Export
        result = _run("export", "--dir", identity_dir)
        assert result.returncode == 0
        card_data = json.loads(result.stdout)
        assert card_data["id"].startswith("did:hermes:")
        assert "proof" in card_data
        assert card_data["proof"]["type"] == "Ed25519Signature2020"

        # Export to file
        export_path = os.path.join(identity_dir, "exported.json")
        result = _run("export", export_path, "--dir", identity_dir)
        assert result.returncode == 0
        assert os.path.exists(export_path)

    def test_03_verify_own_card(self, identity_dir):
        """Verify identity card against itself."""
        password = "verify-test-password!"
        _run("init", "--dir", identity_dir, input_text=f"{password}\n{password}\n")

        card_path = os.path.join(identity_dir, "identity.json")
        result = _run("verify", card_path, "--dir", identity_dir)
        assert result.returncode == 0
        assert "VALID" in result.stdout

    def test_04_sign_and_verify(self, identity_dir):
        """Sign a file and verify the signature."""
        password = "sign-test-password!"
        _run("init", "--dir", identity_dir, input_text=f"{password}\n{password}\n")

        # Create a test file
        test_file = os.path.join(identity_dir, "message.txt")
        Path(test_file).write_text("Hello, hermes-id! This is a signed message.")

        # Sign it
        result = _run("sign", test_file, "--dir", identity_dir, "--password", password)
        assert result.returncode == 0
        assert "Signed" in result.stdout

        # Signature file should exist
        sig_file = test_file + ".sig"
        assert os.path.exists(sig_file)

        # Verify the signature
        card_path = os.path.join(identity_dir, "identity.json")
        result = _run("verify-sig", test_file, sig_file, "--identity", card_path)
        assert result.returncode == 0
        assert "VALID" in result.stdout

    def test_05_verify_rejects_tampered(self, identity_dir):
        """Verification should fail on tampered file."""
        password = "tamper-test-password!"
        _run("init", "--dir", identity_dir, input_text=f"{password}\n{password}\n")

        # Create and sign
        test_file = os.path.join(identity_dir, "message.txt")
        Path(test_file).write_text("Original message.")
        _run("sign", test_file, "--dir", identity_dir, "--password", password)

        # Tamper
        Path(test_file).write_text("TAMPERED message!")

        # Verify should fail
        card_path = os.path.join(identity_dir, "identity.json")
        result = _run("verify-sig", test_file, test_file + ".sig", "--identity", card_path)
        # Should have non-zero return code and INVALID in output
        assert result.returncode != 0 or "INVALID" in result.stdout

    def test_06_status_without_identity(self, identity_dir):
        """Status should report no identity when none exists."""
        result = _run("status", "--dir", identity_dir)
        assert "No identity" in result.stdout

    def test_07_init_with_metadata(self, identity_dir):
        """Init with --profile should store metadata."""
        password = "meta-password!"
        _run("init", "--dir", identity_dir, "--profile", "production",
             input_text=f"{password}\n{password}\n")

        card = IdentityCard.from_json(
            Path(identity_dir, "identity.json").read_text()
        )
        assert card.metadata.get("profile") == "production"

    def test_08_handshake_tcp(self, identity_dir):
        """Full TCP handshake between two identities in temp dirs."""
        import threading

        # Create Alice's identity
        alice_dir = os.path.join(identity_dir, "alice")
        bob_dir = os.path.join(identity_dir, "bob")
        os.makedirs(alice_dir)
        os.makedirs(bob_dir)

        password = "handshake-password!"

        _run("init", "--dir", alice_dir, "--profile", "alice",
             input_text=f"{password}\n{password}\n")
        _run("init", "--dir", bob_dir, "--profile", "bob",
             input_text=f"{password}\n{password}\n")

        # Start Bob as server
        port = 29487  # non-standard port
        stop_file = os.path.join(identity_dir, "stop")
        server_errors = []

        def bob_server():
            try:
                _run("handshake", "listen", "--dir", bob_dir,
                     "--password", password, "--port", str(port))
            except Exception as e:
                server_errors.append(str(e))

        t = threading.Thread(target=bob_server, daemon=True)
        t.start()
        time.sleep(0.5)

        # Alice connects
        result = _run(
            "handshake", "connect", f"127.0.0.1:{port}",
            "--dir", alice_dir, "--password", password,
        )
        print(f"Handshake stdout: {result.stdout}")
        print(f"Handshake stderr: {result.stderr}")

        assert result.returncode == 0
        assert "successful" in result.stdout.lower() or "Authenticated" in result.stdout


class TestCLIEdgeCases:
    """Edge case tests for the CLI."""

    def test_init_existing_no_force(self, identity_dir):
        """Init should warn when identity already exists."""
        password = "edge-password!"
        _run("init", "--dir", identity_dir, input_text=f"{password}\n{password}\n")
        result = _run("init", "--dir", identity_dir, input_text=f"{password}\n{password}\n")
        assert "already exists" in result.stdout or result.returncode != 0

    def test_sign_without_identity(self, identity_dir):
        """Sign should fail cleanly without identity."""
        test_file = os.path.join(identity_dir, "test.txt")
        Path(test_file).write_text("test")
        result = _run("sign", test_file, "--dir", identity_dir, "--password", "x")
        assert result.returncode != 0
        assert "No identity" in result.stdout or "No identity" in result.stderr

    def test_wrong_password(self, identity_dir):
        """Wrong password should fail cleanly."""
        _run("init", "--dir", identity_dir, input_text="good-password!\ngood-password!\n")
        result = _run("sign", os.path.join(identity_dir, "storage.json"),
                      "--dir", identity_dir, "--password", "wrong-password")
        assert result.returncode != 0

    def test_verify_nonexistent_file(self, identity_dir):
        """Verify should fail on missing file."""
        result = _run("verify", "/nonexistent/file.json", "--dir", identity_dir)
        assert result.returncode != 0

    def test_verify_invalid_json(self, identity_dir):
        """Verify should fail on invalid JSON."""
        bad_file = os.path.join(identity_dir, "bad.json")
        Path(bad_file).write_text("not json")
        result = _run("verify", bad_file)
        assert result.returncode != 0

    def test_export_without_identity(self, identity_dir):
        """Export should fail without identity."""
        result = _run("export", "--dir", identity_dir)
        assert result.returncode != 0
        assert "No identity" in result.stdout or "No identity" in result.stderr

    def test_verbose_status_with_metadata(self, identity_dir):
        """Status should show metadata."""
        password = "meta-password!"
        _run("init", "--dir", identity_dir, "--profile", "testing",
             input_text=f"{password}\n{password}\n")
        result = _run("status", "--dir", identity_dir)
        assert "testing" in result.stdout
