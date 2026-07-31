"""
Tests for identity card creation, verification, and formatting.
"""

import json

import pytest

from hermes_id.identity import (
    IdentityCard,
    create_identity,
    verify_identity_card,
    format_identity_card,
)


class TestCreateIdentity:
    def test_create_identity_card(self, identity_card):
        assert identity_card.id.startswith("did:hermes:")
        assert identity_card.controller == identity_card.id
        assert identity_card.proof is not None
        assert identity_card.proof["type"] == "Ed25519Signature2020"

    def test_card_has_all_required_fields(self, identity_card):
        for field in ("id", "controller", "verification_method",
                       "authentication", "assertion_method", "created", "proof"):
            assert getattr(identity_card, field) is not None

    def test_verification_method_has_correct_type(self, identity_card):
        vm = identity_card.verification_method[0]
        assert vm["type"] == "Ed25519VerificationKey2020"
        assert vm["controller"] == identity_card.id
        assert vm["publicKeyMultibase"].startswith("u")

    def test_authentication_links_to_key(self, identity_card):
        expected_key_id = f"{identity_card.id}#keys-1"
        assert identity_card.authentication == [expected_key_id]
        assert identity_card.assertion_method == [expected_key_id]

    def test_metadata_is_stored(self, keypair):
        private, public = keypair
        meta = {"profile": "default", "environment": "production"}
        card = create_identity(private, public, metadata=meta)
        assert card.metadata == meta

    def test_empty_metadata(self, keypair):
        private, public = keypair
        card = create_identity(private, public)
        assert card.metadata == {}

    def test_card_stores_creation_time(self, identity_card):
        import re
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                        identity_card.created)


class TestVerifyIdentityCard:
    def test_verify_valid_card(self, identity_card):
        assert verify_identity_card(identity_card) is True

    def test_verify_missing_proof(self, identity_card, keypair):
        private, public = keypair
        card = IdentityCard(
            id=identity_card.id,
            controller=identity_card.controller,
            verification_method=identity_card.verification_method,
            authentication=identity_card.authentication,
            assertion_method=identity_card.assertion_method,
            created=identity_card.created,
            metadata=identity_card.metadata,
            proof=None,
        )
        assert verify_identity_card(card) is False

    def test_verify_tampered_id(self, identity_card):
        identity_card.id = "did:hermes:EvilDid123"
        assert verify_identity_card(identity_card) is False

    def test_verify_tampered_public_key(self, identity_card):
        vm = identity_card.verification_method[0]
        vm["publicKeyMultibase"] = "uAAAA"  # garbage
        assert verify_identity_card(identity_card) is False

    def test_verify_tampered_signature(self, identity_card):
        sig = identity_card.proof["signatureValue"]
        # Change one character in the base64 signature
        mutated = bytearray(sig.encode())
        mutated[len(mutated) // 2] ^= 1
        identity_card.proof["signatureValue"] = mutated.decode()
        assert verify_identity_card(identity_card) is False

    def test_verify_tampered_created_time(self, identity_card):
        identity_card.created = "2020-01-01T00:00:00Z"
        assert verify_identity_card(identity_card) is False

    def test_verify_tampered_metadata(self, identity_card):
        identity_card.metadata = {"evil": "injected"}
        assert verify_identity_card(identity_card) is False

    def test_verify_circle(self, keypair):
        """Verify works in a circle: create → serialize → deserialize → verify."""
        private, public = keypair
        card = create_identity(private, public, metadata={"test": "roundtrip"})
        json_str = card.to_json()
        loaded = IdentityCard.from_json(json_str)
        assert verify_identity_card(loaded) is True


class TestSerialization:
    def test_to_json_contains_all_fields(self, identity_card):
        json_str = identity_card.to_json()
        data = json.loads(json_str)
        for field in ("id", "controller", "verification_method",
                       "authentication", "assertion_method", "created", "proof"):
            assert field in data

    def test_from_json_roundtrip(self, identity_card):
        json_str = identity_card.to_json()
        loaded = IdentityCard.from_json(json_str)
        assert loaded.id == identity_card.id
        assert loaded.controller == identity_card.controller
        assert loaded.public_key_multibase == identity_card.public_key_multibase
        assert loaded.proof == identity_card.proof
        assert loaded.created == identity_card.created

    def test_from_json_invalid(self):
        with pytest.raises(Exception):
            IdentityCard.from_json("not json")

    def test_from_json_missing_fields(self):
        with pytest.raises(Exception):
            IdentityCard.from_json('{"id": "test"}')


class TestDisplay:
    def test_format_identity_card_contains_did(self, identity_card):
        formatted = format_identity_card(identity_card)
        assert identity_card.id in formatted

    def test_format_identity_card_shows_valid(self, identity_card):
        formatted = format_identity_card(identity_card)
        assert "VALID" in formatted

    def test_format_identity_card_shows_invalid(self):
        card = IdentityCard(
            id="did:hermes:test",
            controller="did:hermes:test",
            verification_method=[],
            authentication=[],
            assertion_method=[],
            created="2026-01-01T00:00:00Z",
            proof=None,
        )
        formatted = format_identity_card(card)
        assert "MISSING PROOF" in formatted

    def test_did_short(self, identity_card):
        short = identity_card.did_short
        assert "did:hermes:" in short

    def test_public_key_multibase(self, identity_card):
        assert identity_card.public_key_multibase.startswith("u")


class TestKeyRotation:
    """Transition-proof signing and verification."""

    def test_rotation_proof_verifies(self, keypair):
        from hermes_id.identity import create_identity, verify_key_rotation
        from hermes_id.crypto import generate_keypair
        old_priv, old_pub = keypair
        old_card = create_identity(old_priv, old_pub, metadata={"gen": 1})
        new_priv, new_pub = generate_keypair()
        new_card = create_identity(
            new_priv, new_pub,
            metadata={"gen": 2},
            previous_card=old_card,
            previous_private_key=old_priv,
        )
        rot = verify_key_rotation(new_card)
        assert rot is not None
        assert rot["previous_did"] == old_card.id
        assert rot["previous_key_fingerprint"] == old_card.public_key_multibase

    def test_no_rotation_metadata_returns_none(self, identity_card):
        from hermes_id.identity import verify_key_rotation
        assert verify_key_rotation(identity_card) is None

    def test_rotation_with_wrong_previous_key_fails(self, keypair):
        from hermes_id.identity import create_identity, verify_key_rotation
        from hermes_id.crypto import generate_keypair
        old_priv, old_pub = keypair
        old_card = create_identity(old_priv, old_pub)
        new_priv, new_pub = generate_keypair()
        # Sign with a DIFFERENT key than the one recorded as previous
        rogue_priv, rogue_pub = generate_keypair()
        rogue_card = create_identity(
            new_priv, new_pub,
            metadata={"gen": 2},
            previous_card=old_card,
            previous_private_key=rogue_priv,
        )
        # Verification must fail because transition sig doesn't match
        # the recorded previous fingerprint
        assert verify_key_rotation(rogue_card) is None

    def test_rotation_tampered_transition_signature_fails(self, keypair):
        from hermes_id.identity import create_identity, verify_key_rotation
        from hermes_id.crypto import generate_keypair
        old_priv, old_pub = keypair
        old_card = create_identity(old_priv, old_pub)
        new_priv, new_pub = generate_keypair()
        new_card = create_identity(
            new_priv, new_pub,
            previous_card=old_card,
            previous_private_key=old_priv,
        )
        # Tamper with the signature
        new_card.metadata["rotation"]["transition_signature"] = "AAABBBCCC"
        assert verify_key_rotation(new_card) is None

    def test_previous_private_key_required(self, keypair):
        from hermes_id.identity import create_identity
        from hermes_id.crypto import generate_keypair
        import pytest as _pytest
        old_priv, old_pub = keypair
        old_card = create_identity(old_priv, old_pub)
        new_priv, new_pub = generate_keypair()
        with _pytest.raises(ValueError):
            create_identity(new_priv, new_pub, previous_card=old_card)

    def test_rotated_card_still_self_verifies(self, keypair):
        from hermes_id.identity import create_identity, verify_identity_card, verify_key_rotation
        from hermes_id.crypto import generate_keypair
        old_priv, old_pub = keypair
        old_card = create_identity(old_priv, old_pub)
        new_priv, new_pub = generate_keypair()
        new_card = create_identity(
            new_priv, new_pub,
            previous_card=old_card,
            previous_private_key=old_priv,
        )
        assert verify_identity_card(new_card)
        assert verify_key_rotation(new_card) is not None
