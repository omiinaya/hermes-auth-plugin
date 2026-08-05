"""
Tests for secure key storage.

Covers: create, unlock, status, config, missing identity, overwrite.
"""

import os
import tempfile
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


# ---------------------------------------------------------------------------
# Config + status edge branches
# ---------------------------------------------------------------------------


class TestStorageConfigBranches:
    def test_config_metadata_none_becomes_empty(self):
        """StorageConfig(metadata=None) normalizes to {} in __post_init__."""
        from hermes_id.storage import StorageConfig

        cfg = StorageConfig(metadata=None)
        assert cfg.metadata == {}

    def test_get_config_reloads_from_file(self, created_identity):
        """get_config() with _config=None reads the on-disk config."""
        storage, _, _ = created_identity
        storage._config = None  # force reload path
        config = storage.get_config()
        assert config.version == 1
        assert config.created_at

    def test_get_config_writes_file_then_reloads(self, tmp_path):
        """A fresh storage with a pre-existing config file loads it."""

        from hermes_id.storage import IdentityStorage, StorageConfig

        d = str(tmp_path / "ident")
        storage = IdentityStorage(directory=d)
        storage.create("password-1234")
        cfg = StorageConfig(version=1, created_at="2026-01-01T00:00:00Z",
                            updated_at="2026-01-02T00:00:00Z", kdf="scrypt")
        storage._write_config(cfg)

        fresh = IdentityStorage(directory=d)
        fresh._config = None
        loaded = fresh.get_config()
        assert loaded.created_at == "2026-01-01T00:00:00Z"
        assert loaded.kdf == "scrypt"

    def test_get_config_no_file_uses_defaults(self, tmp_path):
        """get_config() with no config.json returns a default StorageConfig."""
        from hermes_id.storage import IdentityStorage, StorageConfig

        d = str(tmp_path / "ident")
        storage = IdentityStorage(directory=d)
        storage.create("password-1234")
        # Remove the config file and reset the in-memory cache
        storage._config_path.unlink()
        storage._config = None
        loaded = storage.get_config()
        assert isinstance(loaded, StorageConfig)
        assert loaded.version == 1

    def test_detect_kdf_argon2(self, monkeypatch):
        """_detect_kdf returns argon2id when the argon2 module is present."""
        from hermes_id.storage import IdentityStorage

        assert IdentityStorage._detect_kdf() == "argon2id"

    def test_detect_kdf_scrypt_fallback(self, monkeypatch):
        """Without argon2, _detect_kdf falls back to scrypt."""
        import builtins

        import hermes_id.storage as storage_mod

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "argon2.low_level":
                raise ImportError("argon2 not installed")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        assert storage_mod.IdentityStorage._detect_kdf() == "scrypt"

    def test_detect_kdf_pbkdf2_fallback(self, monkeypatch):
        """Without argon2 and without scrypt support, use pbkdf2."""
        import builtins

        import hermes_id.storage as storage_mod

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "argon2.low_level":
                raise ImportError("argon2 not installed")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        import hashlib

        def boom(*a, **kw):
            raise ValueError("scrypt unavailable")

        monkeypatch.setattr(hashlib, "scrypt", boom)
        assert storage_mod.IdentityStorage._detect_kdf() == "pbkdf2"


class TestKeyContextExit:
    """Branch coverage for _KeyContext.__exit__ edge cases."""

    def test_exit_without_enter_leaves_key_none(self, created_identity):
        """A use_key context whose __enter__ never ran still cleans up on
        __exit__ — der_bytes is None so the zeroing guard is skipped."""
        storage, password, _ = created_identity
        ctx = storage.use_key(password)
        # Calling __exit__ without __enter__ exercises the der_bytes-is-None branch
        ctx.__exit__(None, None, None)
        assert ctx._key is None
        assert ctx._der_bytes is None

    def test_show_status_with_empty_metadata(self):
        """show_status renders a card whose metadata dict is empty — the
        metadata/rotation display lines are skipped."""
        from hermes_id.storage import IdentityStorage

        with tempfile.TemporaryDirectory() as d:
            storage = IdentityStorage(directory=d)
            card = storage.create("password-1234", metadata={})
            assert card.metadata == {}

            # Render with an empty metadata dict → both conditional display
            # lines are skipped.
            status = storage.show_status()
            assert card.id in status
            assert "Metadata:" not in status
            assert "Rotated:" not in status

    def test_rotate_backup_skips_missing_file(self, created_identity):
        """rotate() backups only files that exist — a missing config file is
        skipped without error."""
        storage, password, old_card = created_identity

        # Simulate a partially-deleted identity dir: config file missing.
        cfg_path = Path(storage._dir) / "storage.json"
        assert cfg_path.exists()
        cfg_path.unlink()

        new_card = storage.rotate(password)
        assert new_card.id != old_card.id
        # Backup still holds the files that existed.
        backup_root = Path(storage._dir) / "rotated"
        subs = list(backup_root.iterdir())
        assert len(subs) == 1
        assert (subs[0] / "identity.json").exists()
        assert (subs[0] / "private.enc").exists()


class TestShowStatusMetadataLines:
    def test_show_status_after_rotate_shows_transition(self, created_identity):
        """show_status() reports the rotation transition proof after rotate."""
        storage, password, _ = created_identity
        storage.rotate(password)
        status = storage.show_status()
        assert "Rotated" in status
        assert "transition proof present" in status

    def test_rotation_badge_without_base_metadata(self, tmp_path):
        """A card carrying rotation info but an empty metadata dict renders
        the 'Rotated' badge line."""
        from hermes_id.storage import IdentityStorage

        d = str(tmp_path / "ident")
        storage = IdentityStorage(directory=d)
        storage.create("password-1234")
        storage.rotate("password-1234")  # produces a card with rotation metadata
        status = storage.show_status()
        assert "Rotated:" in status
