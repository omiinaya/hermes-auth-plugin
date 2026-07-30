"""
Fixtures for hermes-id tests.

Shared test helpers: keypair generation, identity cards, temp directories.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from hermes_id.crypto import (
    generate_keypair,
    public_key_bytes,
    derive_did,
    _b64,
)
from hermes_id.identity import (
    IdentityCard,
    create_identity,
)
from hermes_id.storage import IdentityStorage


@pytest.fixture
def keypair():
    """Generate a fresh Ed25519 keypair for tests."""
    return generate_keypair()


@pytest.fixture
def identity_card(keypair):
    """Create a test identity card."""
    private, public = keypair
    return create_identity(private, public, metadata={"test": "fixture"})


@pytest.fixture
def tmp_identity_dir():
    """Create a temporary directory for identity storage tests."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def storage(tmp_identity_dir):
    """Create an IdentityStorage pointing at a temp directory."""
    return IdentityStorage(directory=tmp_identity_dir)


@pytest.fixture
def created_identity(storage):
    """Create a fully initialized identity in a temp directory."""
    password = "test-passphrase-1234-strong!"
    card = storage.create(password, metadata={"profile": "test"})
    return storage, password, card


def assert_valid_card(card: IdentityCard):
    """Assert that an identity card has all required fields."""
    assert card.id.startswith("did:hermes:")
    assert card.controller == card.id
    assert len(card.verification_method) == 1
    assert card.verification_method[0]["type"] == "Ed25519VerificationKey2020"
    assert card.verification_method[0]["publicKeyMultibase"].startswith("u")
    assert len(card.authentication) == 1
    assert len(card.assertion_method) == 1
    assert card.created is not None
    assert card.proof is not None
    assert card.proof["type"] == "Ed25519Signature2020"
    assert card.proof["signatureValue"] is not None
