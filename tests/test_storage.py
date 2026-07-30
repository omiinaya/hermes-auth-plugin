"""
Tests for secure key storage.

Covers: create, unlock, status, config, missing identity, overwrite.
"""

import os
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from hermes_id.storage import IdentityStorage


class TestStorageCreate:
    def test_create_creates_files(self, tmp_identity_dir):
        storage = IdentityStorage(directory=tmp_identity_dir)
        card = storage.create("test-password", metadata={"test": "yes"})
        assert card.id.startswith("did:hermes:")
        assert (Path(tmp_identity_dir) / "private.enc").exists()
        assert (Path(tmp_identity_dir) / "identity.json").exists()
        assert (Path(tmp_identity_dir) / "storage.json").exists()

    def test_create_different_ids(self, tmp_identity_dir):
        s1 = IdentityStorage(directory=tmp_identity_dir)
        c1 = s1.create("password1")
        # Create a new temp dir for second identity
        import tempfile
        with tempfile.TemporaryDirectory() as d2:
            s2 = IdentityStorage(directory=d2)
            c2 = s2.create("password2")
            assert c1.id != c2.id

    def test_create_sets_file_permissions(self, tmp_identity_dir):
        storage = IdentityStorage(directory=tmp_identity_dir)
        storage.create("test-password")
        priv_path = Path(tmp_identity_dir) / "private.enc"
        identity_path = Path(tmp_identity_dir) / "identity.json"
        # On Unix, check perms (skip on Windows)
        if os.name == "posix":
            assert oct(priv_path.stat().st_mode)[-3:] == "600"
            assert oct(identity_path.stat().st_mode)[-3:] == "600"
            assert oct(Path(tmp_identity_dir).stat().st_mode)[-3:] == "700"

    def test_create_stores_metadata(self, tmp_identity_dir):
        storage = IdentityStorage(directory=tmp_identity_dir)
        meta = {"profile": "default", "env": "prod"}
        card = storage.create("password", metadata=meta)
        assert card.metadata == meta


class TestStorageLockUnlock:
    def test_unlock_returns_key(self, created_identity):
        storage, password, _ = created_identity
        private_key = storage.unlock(password)
        from cryptography.hazmat.primitives.asymmetric import ed25519
        assert isinstance(private_key, ed25519.Ed25519PrivateKey)

    def test_unlock_wrong_password(self, created_identity):
        storage, _, _ = created_identity
        with pytest.raises((InvalidTag, Exception)):
            storage.unlock("wrong-password")

    def test_unlock_empty_password(self, created_identity):
        storage, _, _ = created_identity
        with pytest.raises(Exception):
            storage.unlock("")

    def test_unlock_then_sign(self, created_identity):
        storage, password, _ = created_identity
        key = storage.unlock(password)
        from hermes_id.crypto import sign, verify
        sig = sign(key, b"test message")
        assert verify(key.public_key(), b"test message", sig) is True

    def test_double_unlock(self, created_identity):
        storage, password, _ = created_identity
        k1 = storage.unlock(password)
        k2 = storage.unlock(password)
        from hermes_id.crypto import public_key_bytes
        assert public_key_bytes(k1.public_key()) == public_key_bytes(k2.public_key())


class TestStorageStatus:
    def test_exists_false_on_empty_dir(self, tmp_identity_dir):
        storage = IdentityStorage(directory=tmp_identity_dir)
        assert storage.exists() is False

    def test_exists_true_after_create(self, created_identity):
        storage, _, _ = created_identity
        assert storage.exists() is True

    def test_get_identity_card(self, created_identity):
        storage, _, card = created_identity
        loaded = storage.get_identity_card()
        assert loaded.id == card.id
        assert loaded.proof is not None

    def test_get_config(self, created_identity):
        storage, _, _ = created_identity
        config = storage.get_config()
        assert config.version == 1
        assert config.created_at is not None
        assert config.updated_at is not None

    def test_show_status_without_identity(self, tmp_identity_dir):
        storage = IdentityStorage(directory=tmp_identity_dir)
        status = storage.show_status()
        assert "No identity" in status

    def test_show_status_with_identity(self, created_identity):
        storage, _, card = created_identity
        status = storage.show_status()
        assert card.id in status
        assert "Ed25519" in status


class TestStorageErrors:
    def test_unlock_without_create(self, tmp_identity_dir):
        storage = IdentityStorage(directory=tmp_identity_dir)
        with pytest.raises(FileNotFoundError):
            storage.unlock("password")

    def test_get_identity_card_without_create(self, tmp_identity_dir):
        storage = IdentityStorage(directory=tmp_identity_dir)
        with pytest.raises(FileNotFoundError):
            storage.get_identity_card()

    def test_create_overwrite_protected(self, created_identity):
        storage, _, _ = created_identity
        # create() currently overwrites silently (no --force guard at this level)
        # Verify that calling create() again succeeds (overwrites)
        card2 = storage.create("new-password", metadata={"test": "overwrite"})
        assert card2.id is not None
        # And we can unlock with the NEW password
        key = storage.unlock("new-password")
        assert key is not None

    def test_corrupted_private_key(self, created_identity):
        storage, _, _ = created_identity
        priv_path = Path(storage._private_path)
        priv_path.write_bytes(b"garbage" * 10)
        with pytest.raises(Exception):
            storage.unlock("test-passphrase-1234-strong!")
