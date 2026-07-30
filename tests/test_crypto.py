"""
Tests for cryptographic primitives.

Covers: key generation, signing/verification, key serialization,
key encryption/decryption, DID derivation, and session key derivation.
"""

import hashlib
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from hermes_id.crypto import (
    generate_keypair,
    sign,
    verify,
    serialize_private_key,
    deserialize_private_key,
    serialize_public_key,
    deserialize_public_key,
    public_key_bytes,
    generate_x25519_keypair,
    x25519_shared_secret,
    derive_session_key,
    encrypt_key,
    decrypt_key,
    generate_challenge,
    derive_did,
    CHALLENGE_SIZE,
    _b64,
    _unb64,
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
