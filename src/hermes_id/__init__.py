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

__version__ = "1.4.3"

from hermes_id.crypto import (
    decrypt_key,
    derive_session_key,
    encrypt_key,
    generate_keypair,
    secure_zero,
    sign,
    verify,
)
from hermes_id.handshake import (
    HandshakeError,
    HandshakeMessage,
    HandshakeProtocol,
    HandshakeState,
)
from hermes_id.identity import (
    IdentityCard,
    create_identity,
    format_identity_card,
    verify_identity_card,
)
from hermes_id.sdk import (
    ENV_PROJECT,
    ENV_SERVER_URL,
    AuthError,
    RevocationChecker,
    TokenCache,
    default_card_cache_path,
    load_server_card,
    verify_token_offline,
)
from hermes_id.storage import (
    IdentityStorage,
    StorageConfig,
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
    "secure_zero",
    # Identity
    "IdentityCard",
    "create_identity",
    "verify_identity_card",
    "format_identity_card",
    # App-side SDK
    "AuthError",
    "ENV_SERVER_URL",
    "ENV_PROJECT",
    "TokenCache",
    "RevocationChecker",
    "default_card_cache_path",
    "load_server_card",
    "verify_token_offline",
    # Storage
    "IdentityStorage",
    "StorageConfig",
    # Handshake
    "HandshakeProtocol",
    "HandshakeState",
    "HandshakeMessage",
    "HandshakeError",
]
