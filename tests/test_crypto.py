"""
Tests for cryptographic primitives.

Covers: key generation, signing/verification, key serialization,
key encryption/decryption, DID derivation, and session key derivation.
"""

import os
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hermes_id.crypto import (
    CHALLENGE_SIZE,
    _b64,
    _unb64,
    decrypt_key,
    derive_did,
    derive_session_key,
    deserialize_private_key,
    deserialize_public_key,
    encrypt_key,
    generate_challenge,
    generate_keypair,
    generate_x25519_keypair,
    public_key_bytes,
    serialize_private_key,
    serialize_public_key,
    sign,
    verify,
    x25519_shared_secret,
)


class TestKeyGeneration:
    def test_generate_keypair_returns_ed25519(self):
        private, public = generate_keypair()
        assert isinstance(private, ed25519.Ed25519PrivateKey)
        assert isinstance(public, ed25519.Ed25519PublicKey)

    def test_keypair_is_deterministically_random(self):
        k1 = generate_keypair()
        k2 = generate_keypair()
        pk1_bytes = public_key_bytes(k1[1])
        pk2_bytes = public_key_bytes(k2[1])
        assert pk1_bytes != pk2_bytes

    def test_public_key_32_bytes(self, keypair):
        _, public = keypair
        raw = public_key_bytes(public)
        assert len(raw) == 32


class TestSigning:
    def test_sign_and_verify(self, keypair):
        private, public = keypair
        message = b"Hello, hermes-id!"
        sig = sign(private, message)
        assert len(sig) == 64  # Ed25519 signature size
        assert verify(public, message, sig) is True

    def test_verify_rejects_tampered_message(self, keypair):
        private, public = keypair
        message = b"Original message"
        sig = sign(private, message)
        assert verify(public, b"Tampered message", sig) is False

    def test_verify_rejects_tampered_signature(self, keypair):
        private, public = keypair
        message = b"Test"
        sig = sign(private, message)
        # Flip a bit in the signature
        tampered = bytearray(sig)
        tampered[0] ^= 0x01
        assert verify(public, message, bytes(tampered)) is False

    def test_verify_rejects_wrong_key(self):
        k1 = generate_keypair()
        k2 = generate_keypair()
        message = b"Test"
        sig = sign(k1[0], message)
        assert verify(k2[1], message, sig) is False

    def test_verify_empty_message(self, keypair):
        private, public = keypair
        sig = sign(private, b"")
        assert verify(public, b"", sig) is True
        assert verify(public, b"x", sig) is False

    def test_verify_large_message(self, keypair):
        private, public = keypair
        message = os.urandom(1024 * 1024)  # 1 MB
        sig = sign(private, message)
        assert verify(public, message, sig) is True


class TestKeySerialization:
    def test_private_key_roundtrip(self, keypair):
        private, _ = keypair
        der = serialize_private_key(private)
        assert len(der) > 0
        loaded = deserialize_private_key(der)
        # Verify the loaded key works
        sig = sign(loaded, b"test")
        public = private.public_key()
        assert verify(public, b"test", sig) is True

    def test_public_key_roundtrip(self, keypair):
        _, public = keypair
        der = serialize_public_key(public)
        assert len(der) > 0
        loaded = deserialize_public_key(der)
        raw_original = public_key_bytes(public)
        raw_loaded = public_key_bytes(loaded)
        assert raw_original == raw_loaded

    def test_public_key_bytes_raw(self, keypair):
        _, public = keypair
        raw = public_key_bytes(public)
        assert len(raw) == 32
        # Can reconstruct from raw bytes
        reconstructed = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        assert public_key_bytes(reconstructed) == raw


class TestKeyEncryption:
    def test_encrypt_decrypt_roundtrip(self, keypair):
        private, _ = keypair
        der = serialize_private_key(private)
        password = "correct-horse-battery-staple-1234!"
        encrypted = encrypt_key(der, password)
        assert encrypted != der
        assert len(encrypted) > len(der)  # has salt + nonce + tag overhead

        decrypted = decrypt_key(encrypted, password)
        assert decrypted == der

    def test_decrypt_wrong_password(self, keypair):
        private, _ = keypair
        der = serialize_private_key(private)
        encrypted = encrypt_key(der, "correct-password")
        with pytest.raises(Exception):  # InvalidTag
            decrypt_key(encrypted, "wrong-password")

    def test_encrypt_empty_key_material(self):
        """Test that encrypting empty bytes still works."""
        encrypted = encrypt_key(b"", "password")
        decrypted = decrypt_key(encrypted, "password")
        assert decrypted == b""

    def test_encrypt_tampered_blob(self, keypair):
        private, _ = keypair
        der = serialize_private_key(private)
        encrypted = bytearray(encrypt_key(der, "password"))
        encrypted[20] ^= 0xFF  # Corrupt the nonce
        with pytest.raises(Exception):
            decrypt_key(bytes(encrypted), "password")

    def test_v3_blob_has_self_describing_header(self, keypair):
        """v3 blobs carry the KDF id AND its exact parameters (portable)."""
        private, _ = keypair
        der = serialize_private_key(private)
        blob = encrypt_key(der, "password")
        assert blob[:4] == b"HID3"
        kdf_id = blob[4]
        assert kdf_id in (0, 1, 2)  # argon2id / scrypt / pbkdf2
        # Params block present (12 bytes, big-endian u32 triple)
        a, b, c = struct.unpack(">III", blob[5:17])
        assert (a, b, c) != (0, 0, 0)
        # Decrypt works (uses the recorded KDF + params)
        assert decrypt_key(blob, "password") == der

    def test_v3_blob_uses_recorded_params_not_code_defaults(self, keypair):
        """A v3 blob with unusual scrypt params decrypts even though the
        code defaults differ — proving params come from the blob."""
        from hermes_id.crypto import (
            _BLOB_MAGIC_V3,
            _KDF_SCRYPT,
            _derive_storage_key_with_kdf,
            _pack_params,
        )

        private, _ = keypair
        der = serialize_private_key(private)
        password = "params-test-password"
        salt = os.urandom(16)
        nonce = os.urandom(12)
        unusual = (2**10, 8, 1)  # tiny scrypt cost — definitely != code default (2^17)
        key = _derive_storage_key_with_kdf(password, salt, _KDF_SCRYPT, unusual)
        ciphertext = AESGCM(key).encrypt(nonce, der, None)
        blob = (
            _BLOB_MAGIC_V3
            + bytes([_KDF_SCRYPT])
            + _pack_params(*unusual)
            + salt
            + nonce
            + ciphertext
        )
        assert decrypt_key(blob, password) == der

    def test_v2_legacy_blob_still_decrypts(self, keypair):
        """Historical HID2 blobs (KDF id, no params) keep decrypting via
        the pinned legacy parameters (pbkdf2 path — parameters unchanged)."""
        from hermes_id.crypto import (
            _BLOB_MAGIC_V2,
            _KDF_PBKDF2,
            _derive_storage_key_with_kdf,
            _legacy_params_for,
        )

        private, _ = keypair
        der = serialize_private_key(private)
        password = "legacy-v2-password"
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = _derive_storage_key_with_kdf(
            password, salt, _KDF_PBKDF2, _legacy_params_for(_KDF_PBKDF2)
        )
        ciphertext = AESGCM(key).encrypt(nonce, der, None)
        blob = _BLOB_MAGIC_V2 + bytes([_KDF_PBKDF2]) + salt + nonce + ciphertext
        assert decrypt_key(blob, password) == der

    def test_legacy_scrypt_params_are_pinned(self):
        """The legacy scrypt parameters must stay at their historical values
        (N=2^20) or old v1/v2 blobs become undecryptable."""
        from hermes_id.crypto import (
            _KDF_SCRYPT,
            _legacy_params_for,
        )

        assert _legacy_params_for(_KDF_SCRYPT) == (2**20, 8, 1)

    def test_legacy_v1_blob_decrypts_across_kdfs(self, keypair):
        """A legacy (headerless) blob decrypts no matter which KDF it used.

        Legacy blobs were created with the pinned legacy parameters (scrypt
        N=2^20, argon2id 3/65536/4, pbkdf2 600k) — the ones in effect before
        the v3 format recorded parameters.
        """
        from hermes_id.crypto import (
            _KDF_ARGON2,
            _KDF_PBKDF2,
            _KDF_SCRYPT,
            _derive_storage_key_with_kdf,
            _legacy_params_for,
        )

        private, _ = keypair
        der = serialize_private_key(private)
        password = "portability-test-password"
        for kdf, name in ((_KDF_ARGON2, "argon2id"), (_KDF_SCRYPT, "scrypt"), (_KDF_PBKDF2, "pbkdf2")):
            salt = os.urandom(16)
            nonce = os.urandom(12)
            try:
                key = _derive_storage_key_with_kdf(
                    password, salt, kdf, _legacy_params_for(kdf)
                )
            except ImportError:
                continue  # argon2 not installed in this test env
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, der, None)
            legacy_blob = salt + nonce + ciphertext  # no header
            assert decrypt_key(legacy_blob, password) == der, f"legacy {name} blob failed"


class TestX25519:
    def test_x25519_shared_secret(self):
        alice_priv, alice_pub = generate_x25519_keypair()
        bob_priv, bob_pub = generate_x25519_keypair()
        alice_shared = x25519_shared_secret(alice_priv, bob_pub)
        bob_shared = x25519_shared_secret(bob_priv, alice_pub)
        assert alice_shared == bob_shared
        assert len(alice_shared) == 32

    def test_x25519_is_unique(self):
        alice_priv, alice_pub = generate_x25519_keypair()
        bob_priv, bob_pub = generate_x25519_keypair()
        charlie_priv, charlie_pub = generate_x25519_keypair()
        ab = x25519_shared_secret(alice_priv, bob_pub)
        ac = x25519_shared_secret(alice_priv, charlie_pub)
        assert ab != ac

    def test_session_key_derivation(self):
        alice_priv, alice_pub = generate_x25519_keypair()
        bob_priv, bob_pub = generate_x25519_keypair()
        shared = x25519_shared_secret(alice_priv, bob_pub)
        key = derive_session_key(shared)
        assert len(key) == 32  # AES-256 key size

        # Same shared secret produces same session key
        shared2 = x25519_shared_secret(bob_priv, alice_pub)
        key2 = derive_session_key(shared2)
        assert key == key2

    def test_session_key_context_isolation(self):
        alice_priv, alice_pub = generate_x25519_keypair()
        bob_priv, bob_pub = generate_x25519_keypair()
        shared = x25519_shared_secret(alice_priv, bob_pub)
        key1 = derive_session_key(shared, context=b"app/v1")
        key2 = derive_session_key(shared, context=b"app/v2")
        assert key1 != key2


class TestChallenge:
    def test_challenge_size(self):
        c = generate_challenge()
        assert len(c) == CHALLENGE_SIZE  # 32 bytes

    def test_challenge_is_random(self):
        c1 = generate_challenge()
        c2 = generate_challenge()
        assert c1 != c2

    def test_challenge_custom_size(self):
        c = generate_challenge(16)
        assert len(c) == 16


class TestDID:
    def test_derive_did_format(self, keypair):
        _, public = keypair
        did = derive_did(public)
        assert did.startswith("did:hermes:")
        assert len(did) > len("did:hermes:")

    def test_did_derives_from_pubkey(self, keypair):
        _, public = keypair
        did1 = derive_did(public)
        did2 = derive_did(public)
        assert did1 == did2  # deterministic

    def test_different_keys_produce_different_dids(self):
        k1 = generate_keypair()[1]
        k2 = generate_keypair()[1]
        assert derive_did(k1) != derive_did(k2)


# ---------------------------------------------------------------------------
# Remaining defensive branches
# ---------------------------------------------------------------------------


class TestSecureZero:
    def test_secure_zero_empty(self):
        """secure_zero on empty bytes is a no-op."""
        from hermes_id.crypto import secure_zero

        secure_zero(b"")  # must not raise

    def test_secure_zero_bytearray(self):
        """secure_zero zeroes a mutable bytearray in place."""
        from hermes_id.crypto import secure_zero

        data = bytearray(b"secret")
        secure_zero(data)
        assert all(b == 0 for b in data)


class TestDeserializePublicKey:
    def test_rejects_non_ed25519_key(self):
        """deserialize_public_key rejects an RSA public key DER."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        from hermes_id.crypto import deserialize_public_key

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        der = rsa_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        with pytest.raises(ValueError, match="Expected Ed25519"):
            deserialize_public_key(der)


class TestBlobParams:
    def test_scrypt_blob_params(self):
        """_blob_params_for returns the current scrypt defaults for KDF 1."""
        from hermes_id.crypto import _KDF_SCRYPT, _blob_params_for

        assert _blob_params_for(_KDF_SCRYPT) == (2**17, 8, 1)

    def test_pbkdf2_blob_params_default(self):
        from hermes_id.crypto import _KDF_PBKDF2, _blob_params_for

        params = _blob_params_for(_KDF_PBKDF2)
        assert params[0] > 0  # iterations
        assert params[1:] == (0, 0)


class TestKdfIdFallbacks:
    def test_kdf_id_argon2_default(self):
        """_kdf_id returns argon2id in this environment."""
        from hermes_id.crypto import _KDF_ARGON2, _kdf_id

        assert _kdf_id() == _KDF_ARGON2

    def test_kdf_id_scrypt_fallback(self, monkeypatch):
        """Without argon2, _kdf_id falls back to scrypt."""
        import builtins

        import hermes_id.crypto as crypto_mod

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "argon2.low_level":
                raise ImportError("argon2 not installed")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        crypto_mod._kdf_id.cache_clear()
        assert crypto_mod._kdf_id() == crypto_mod._KDF_SCRYPT

    def test_kdf_id_pbkdf2_fallback(self, monkeypatch):
        """Without argon2 and scrypt, _kdf_id falls back to pbkdf2."""
        import builtins
        import hashlib

        import hermes_id.crypto as crypto_mod

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "argon2.low_level":
                raise ImportError("argon2 not installed")
            return real_import(name, *a, **kw)

        def boom(*a, **kw):
            raise ValueError("scrypt unavailable")

        monkeypatch.setattr(builtins, "__import__", fake_import)
        monkeypatch.setattr(hashlib, "scrypt", boom)
        crypto_mod._kdf_id.cache_clear()
        assert crypto_mod._kdf_id() == crypto_mod._KDF_PBKDF2


class TestDeriveStorageKey:
    def test_wrapper_derives_with_environment_kdf(self):
        """_derive_storage_key uses the environment's strongest KDF."""
        from hermes_id.crypto import _derive_storage_key

        key = _derive_storage_key("password", b"0123456789abcdef")
        assert len(key) == 32

class TestDecryptKeyAllKdfsFail:
    def test_legacy_v1_blob_all_kdfs_fail_raises(self, keypair):
        """A legacy blob that no KDF can decrypt raises (not silently None)."""
        import os

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        from hermes_id.crypto import (
            _KDF_SCRYPT,
            _derive_storage_key_with_kdf,
            _legacy_params_for,
            decrypt_key,
        )

        private, _ = keypair
        from hermes_id.crypto import serialize_private_key

        der = serialize_private_key(private)
        # Build a blob with a KNOWN key, then corrupt the ciphertext so
        # every KDF's GCM tag check fails.
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = _derive_storage_key_with_kdf(
            "password", salt, _KDF_SCRYPT, _legacy_params_for(_KDF_SCRYPT)
        )
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, der, None)
        # Flip bytes in the tag region so decryption fails for all KDFs
        corrupted = salt + nonce + ciphertext[:-4] + bytes(
            b ^ 0xFF for b in ciphertext[-4:]
        )
        with pytest.raises(Exception):  # InvalidTag from the last KDF
            decrypt_key(corrupted, "password")

    def test_legacy_v1_blob_kdf_unavailable_skips(self, keypair, monkeypatch):
        """A KDF ImportError inside the v1 loop is skipped, not fatal."""
        import os

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        from hermes_id.crypto import (
            _KDF_ARGON2,
            _KDF_SCRYPT,
            _derive_storage_key_with_kdf,
            _legacy_params_for,
            decrypt_key,
        )

        private, _ = keypair
        from hermes_id.crypto import serialize_private_key

        der = serialize_private_key(private)
        salt = os.urandom(16)
        nonce = os.urandom(12)
        # Build a scrypt-encrypted blob: argon2 will ImportError (skip),
        # scrypt succeeds → the loop must continue past the ImportError.
        key = _derive_storage_key_with_kdf(
            "password", salt, _KDF_SCRYPT, _legacy_params_for(_KDF_SCRYPT)
        )
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, der, None)
        blob = salt + nonce + ciphertext

        real_derive = _derive_storage_key_with_kdf
        calls: dict = {"kdfs": []}

        def flaky_derive(password, salt, kdf, params):
            calls["kdfs"].append(kdf)
            if kdf == _KDF_ARGON2:
                raise ImportError("argon2 unavailable")
            return real_derive(password, salt, kdf, params)

        monkeypatch.setattr(
            "hermes_id.crypto._derive_storage_key_with_kdf", flaky_derive
        )
        # First KDF (argon2) raises ImportError → skipped; scrypt decrypts.
        assert decrypt_key(blob, "password") == der
        assert calls["kdfs"][0] == _KDF_ARGON2
        assert calls["kdfs"][1] == _KDF_SCRYPT

    def test_legacy_v1_blob_all_kdfs_import_error_raises_invalid_tag(self, keypair, monkeypatch):
        """When every KDF raises ImportError, decrypt_key raises InvalidTag
        (not the ImportError, and not None)."""
        import os

        from cryptography.exceptions import InvalidTag as CInvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        from hermes_id.crypto import (
            decrypt_key,
        )

        private, _ = keypair
        from hermes_id.crypto import serialize_private_key

        der = serialize_private_key(private)
        salt = os.urandom(16)
        nonce = os.urandom(12)
        # Key material doesn't matter — every derivation will ImportError
        bogus_key = b"K" * 32
        aesgcm = AESGCM(bogus_key)
        ciphertext = aesgcm.encrypt(nonce, der, None)
        blob = salt + nonce + ciphertext

        def always_import_error(password, salt, kdf, params):
            raise ImportError("no KDF available")

        monkeypatch.setattr(
            "hermes_id.crypto._derive_storage_key_with_kdf", always_import_error
        )
        with pytest.raises(CInvalidTag):
            decrypt_key(blob, "password")


class TestEncoding:
    def test_b64_roundtrip(self):
        data = os.urandom(256)
        encoded = _b64(data)
        decoded = _unb64(encoded)
        assert decoded == data

    def test_b64_no_padding(self):
        encoded = _b64(b"test data that is 16 bytes")
        assert "=" not in encoded

    def test_b64_empty(self):
        assert _b64(b"") == ""
        assert _unb64("") == b""
