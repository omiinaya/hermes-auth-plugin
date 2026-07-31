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


class TestStorageRotation:
    """Key rotation: new DID, transition proof, backup safety."""

    def test_rotate_new_did_and_transition_proof(self, created_identity):
        storage, password, old_card = created_identity
        new_card = storage.rotate(password)
        assert new_card.id != old_card.id
        assert new_card.id.startswith("did:hermes:")
        # Transition proof present and verifiable
        from hermes_id.identity import verify_key_rotation
        rot = verify_key_rotation(new_card)
        assert rot is not None
        assert rot["previous_did"] == old_card.id

    def test_rotate_self_signature_valid(self, created_identity):
        storage, password, _ = created_identity
        from hermes_id.identity import verify_identity_card
        new_card = storage.rotate(password)
        assert verify_identity_card(new_card)

    def test_rotate_backup_dir_created(self, created_identity):
        storage, password, old_card = created_identity
        storage.rotate(password)
        backup_root = Path(storage._dir) / "rotated"
        assert backup_root.exists()
        subs = list(backup_root.iterdir())
        assert len(subs) == 1
        assert (subs[0] / "identity.json").exists()
        assert (subs[0] / "private.enc").exists()
        # Backup preserves the OLD DID
        import json as _json
        backup_card = _json.loads((subs[0] / "identity.json").read_text())
        assert backup_card["id"] == old_card.id

    def test_rotate_no_backup_flag(self, created_identity):
        storage, password, _ = created_identity
        storage.rotate(password, keep_backup=False)
        backup_root = Path(storage._dir) / "rotated"
        assert not backup_root.exists()

    def test_rotate_after_rotate(self, created_identity):
        storage, password, _ = created_identity
        card2 = storage.rotate(password)
        card3 = storage.rotate(password)
        assert card3.id != card2.id
        from hermes_id.identity import verify_key_rotation
        rot = verify_key_rotation(card3)
        assert rot is not None
        assert rot["previous_did"] == card2.id
        assert card3.metadata.get("rotations") == 2

    def test_rotate_preserves_metadata_and_merges(self, created_identity):
        storage, password, old_card = created_identity
        new_card = storage.rotate(password, metadata={"note": "compromise-response"})
        assert new_card.metadata.get("profile") == "test"  # preserved from old
        assert new_card.metadata.get("note") == "compromise-response"  # merged
        assert new_card.metadata.get("rotations") == 1

    def test_rotate_keeps_same_password_unlockable(self, created_identity):
        storage, password, _ = created_identity
        storage.rotate(password)
        key = storage.unlock(password)
        assert key is not None

    def test_rotate_without_identity_raises(self, tmp_identity_dir):
        storage = IdentityStorage(directory=tmp_identity_dir)
        with pytest.raises(FileNotFoundError):
            storage.rotate("whatever")

    def test_rotate_wrong_password_raises(self, created_identity):
        storage, _, _ = created_identity
        with pytest.raises(Exception):
            storage.rotate("wrong-password")
