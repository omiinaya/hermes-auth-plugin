"""
hermes-id — Self-Sovereign Identity for Hermes Agent Instances.

Each Hermes instance gets a unique Ed25519 keypair. The public half is
packaged into a self-signed *identity card* (a Verifiable Credential in
DID-compatible format). The private half never leaves the instance,
encrypted at rest with AES-256-GCM.

When two instances (or an instance and a third-party service) need to
authenticate, they perform a **mutual challenge-response handshake**:

    1. Verifier generates a cryptographic nonce
    2. Prover signs the nonce with their private key
    3. Verifier checks the signature against the prover's identity card
    4. (Mutual) Both sides repeat in opposite direction

The protocol provides replay-proof, forward-compatible authentication
without any central registry or PKI.
"""

__version__ = "1.0.0"

from hermes_id.crypto import (
    generate_keypair,
    sign,
    verify,
    encrypt_key,
    decrypt_key,
    derive_session_key,
    secure_zero,
)
from hermes_id.identity import (
    IdentityCard,
    create_identity,
    verify_identity_card,
    format_identity_card,
)
from hermes_id.storage import (
    IdentityStorage,
    StorageConfig,
)
from hermes_id.handshake import (
    HandshakeProtocol,
    HandshakeState,
    HandshakeMessage,
    HandshakeError,
)

__all__ = [
    # Version
    "__version__",
    # Crypto
    "generate_keypair",
    "sign",
    "verify",
    "encrypt_key",
    "decrypt_key",
    "derive_session_key",
    # Identity
    "IdentityCard",
    "create_identity",
    "verify_identity_card",
    "format_identity_card",
    # Storage
    "IdentityStorage",
    "StorageConfig",
    # Handshake
    "HandshakeProtocol",
    "HandshakeState",
    "HandshakeMessage",
    "HandshakeError",
]
