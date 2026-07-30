"""
Identity document management — the "identity card" for a Hermes Agent instance.

An ``IdentityCard`` is a self-signed JSON document (DID-compatible Verifiable
Credential) that carries:

- The instance's Decentralized Identifier (DID)
- Its Ed25519 public key
- Metadata (creation time, profile name, optional attributes)
- A self-signature proving control of the private key

The identity card is **public** — share it freely.  It proves nothing by
itself.  The holder proves ownership by signing a challenge (see
:mod:`hermes_id.handshake`).
"""

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from hermes_id.crypto import (
    derive_did,
    public_key_bytes,
    serialize_public_key,
    sign,
    verify,
    _b64,
    _unb64,
    _multibase_encode,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CONTEXT_URL = "https://hermes-id.proto/v1"
_IDENTITY_TYPE = "HermesAgentIdentity"
_KEY_TYPE = "Ed25519VerificationKey2020"
_PROOF_TYPE = "Ed25519Signature2020"
_PROOF_PURPOSE = "assertionMethod"

# ---------------------------------------------------------------------------
# Identity Card
# ---------------------------------------------------------------------------

@dataclass
class IdentityCard:
    """A self-signed identity document for a Hermes Agent instance.

    **Do not** construct directly — use :func:`create_identity` instead.

    Attributes:
        id: DID string, e.g. ``did:hermes:abc123...``
        controller: Same DID (self-sovereign).
        verification_method: List of public key descriptions.
        authentication: List of key IDs usable for auth.
        assertion_method: List of key IDs usable for signing.
        created: ISO-8601 creation timestamp.
        metadata: Optional key-value claims (profile name, etc.).
        proof: Self-signature proving key control.
    """
    id: str
    controller: str
    verification_method: list[dict[str, str]]
    authentication: list[str]
    assertion_method: list[str]
    created: str
    metadata: dict[str, Any] = field(default_factory=dict)
    proof: Optional[dict[str, str]] = None

    def to_json(self, indent: int = 2) -> str:
        """Serialize the identity card to pretty-printed JSON."""
        return json.dumps(asdict(self), indent=indent, ensure_ascii=False)

    @classmethod
    def from_json(cls, raw: str) -> "IdentityCard":
        """Deserialize an identity card from JSON string."""
        data = json.loads(raw)
        return cls(**data)

    @property
    def public_key_multibase(self) -> str:
        """Extract the multibase-encoded public key from verification_method."""
        if self.verification_method:
            return self.verification_method[0].get("publicKeyMultibase", "")
        return ""

    @property
    def did_short(self) -> str:
        """Short display form: ``did:hermes:abc...`` (first 8 + last 4)."""
        suffix = self.id.split(":")[-1]
        if len(suffix) > 12:
            return f"did:hermes:{suffix[:8]}...{suffix[-4:]}"
        return self.id


def create_identity(
    private_key: ed25519.Ed25519PrivateKey,
    public_key: ed25519.Ed25519PublicKey,
    metadata: Optional[dict[str, Any]] = None,
) -> IdentityCard:
    """Create a self-signed identity card for an Ed25519 keypair.

    Steps:
        1. Derive the DID from the public key hash
        2. Build the key description
        3. Serialize the card (without proof)
        4. Sign the serialized card with the private key
        5. Embed the proof

    Args:
        private_key: The instance's Ed25519 private key.
        public_key: The corresponding public key.
        metadata: Optional claims (e.g. ``{"profile": "default"}``).

    Returns:
        A fully self-signed ``IdentityCard``.
    """
    did = derive_did(public_key)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pub_b58 = _multibase_encode(public_key_bytes(public_key))
    key_id = f"{did}#keys-1"

    card = IdentityCard(
        id=did,
        controller=did,
        verification_method=[{
            "id": key_id,
            "type": _KEY_TYPE,
            "controller": did,
            "publicKeyMultibase": pub_b58,
        }],
        authentication=[key_id],
        assertion_method=[key_id],
        created=created,
        metadata=metadata or {},
        proof=None,
    )

    # Self-sign: serialize without proof, then sign the canonical JSON
    proof_data = card.to_json()  # JSON without proof (proof is None)
    signature = sign(private_key, proof_data.encode("utf-8"))

    card.proof = {
        "type": _PROOF_TYPE,
        "created": created,
        "verificationMethod": key_id,
        "proofPurpose": _PROOF_PURPOSE,
        "signatureValue": _b64(signature),
    }

    return card


def verify_identity_card(card: IdentityCard) -> bool:
    """Verify the self-signature on an identity card.

    Reconstructs the pre-proof JSON, extracts the signature, and checks
    it against the embedded public key.

    Returns:
        True if the signature is valid and the document is untampered.
    """
    if not card.proof:
        return False

    # Separate proof from the rest of the document
    proof = card.proof
    signature_b64 = proof.get("signatureValue", "")
    if not signature_b64:
        return False

    signature_bytes = _unb64(signature_b64)

    # Rebuild the pre-proof JSON
    card_no_proof = IdentityCard(
        id=card.id,
        controller=card.controller,
        verification_method=card.verification_method,
        authentication=card.authentication,
        assertion_method=card.assertion_method,
        created=card.created,
        metadata=card.metadata,
        proof=None,
    )
    canonical = card_no_proof.to_json()

    # Recover public key from verification_method
    pub_b58 = card.public_key_multibase
    if not pub_b58:
        return False

    # Decode multibase: first char is prefix ('u' for base64url, 'z' for base58btc)
    pub_raw = _unb64(pub_b58[1:])  # strip prefix 'u'

    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
    except Exception:
        return False

    return verify(public_key, canonical.encode("utf-8"), signature_bytes)


def format_identity_card(card: IdentityCard) -> str:
    """Render an identity card as a human-readable summary."""
    lines = [
        "╔══════════════════════════════════════╗",
        "║       HERMES IDENTITY CARD           ║",
        "╠══════════════════════════════════════╣",
        f"  DID:           {card.id}",
        f"  Created:       {card.created}",
        f"  Key Type:      {_KEY_TYPE}",
        f"  Signed:        {'✅ VALID' if card.proof else '❌ MISSING PROOF'}",
    ]
    if card.metadata:
        for k, v in card.metadata.items():
            lines.append(f"  {k.capitalize()}:    {v}")
    lines.append("╚══════════════════════════════════════╝")
    return "\n".join(lines)
