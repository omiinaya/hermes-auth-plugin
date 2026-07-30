# Handshake Protocol Specification v1.0

> **Protocol name:** Hermes-ID Mutual Authentication Protocol
> **Version:** 1.0
> **Signature scheme:** Ed25519 (EdDSA on Curve25519)
> **Key agreement (optional):** X25519 ECDH + HKDF-SHA256

## Overview

This document specifies the wire protocol for mutual authentication between
two parties (each holding an Ed25519 keypair). The protocol is:

- **Stateless:** Each handshake is independent. No session state is stored
  between handshakes.
- **Self-authenticating:** Proof of identity is borne entirely by
  cryptographic signatures — no CA, no PKI, no blockchain.
- **Extensible:** The `protocols` and `version` fields allow future upgrades.

## Transport

The protocol is transport-agnostic. The reference implementation uses **TCP**
with the following framing:

```
[4 bytes: big-endian payload length]
[N bytes: JSON-encoded message]
```

Maximum message size: 64 KB. Handshake timeout: 30 seconds.

Default port: **9487** (HERM on a telephone keypad).

## Message Types

All messages are JSON objects with a mandatory `type` field.

### 1. HELLO (Initiator → Responder)

Sent by the initiator to begin a handshake.

```json
{
  "type": "hello",
  "version": "1.0",
  "from": "did:hermes:<initiator_did>",
  "protocols": ["ed25519-challenge-v1"]
}
```

Fields:
- `version`: Protocol version string (MAJOR.MINOR). Backwards-incompatible
  changes increment MAJOR. Backwards-compatible additions increment MINOR.
- `from`: The initiator's DID.
- `protocols`: List of supported authentication protocols. The responder
  selects one for the challenge. Currently only `ed25519-challenge-v1`.

### 2. CHALLENGE (Responder → Initiator)

Sent by the responder after receiving HELLO. Contains a random challenge
signed by the responder's private key.

```json
{
  "type": "challenge",
  "challenge": "<base64url(32_random_bytes)>",
  "from": "did:hermes:<responder_did>",
  "signature": "<base64url(Ed25519_signature_over_challenge)>"
}
```

Fields:
- `challenge`: 32 bytes of kernel randomness, base64url-encoded.
- `from`: The responder's DID.
- `signature`: Ed25519 signature over the raw `challenge` bytes. Allows
  the initiator to verify the challenge came from the claimed responder.

### 3. AUTH (Initiator → Responder)

Sent by the initiator to prove their identity. Contains the full identity
card and a signature proving control of the private key.

```json
{
  "type": "auth",
  "identity_card": "<JSON string of initiator's full identity card>",
  "challenge": "<echoed base64url challenge from step 2>",
  "signature": "<base64url(Ed25519(challenge || responder_did))>"
}
```

Fields:
- `identity_card`: The initiator's complete identity card serialized as a
  **JSON string** (not a nested object). The responder must parse this and
  verify its self-signature.
- `challenge`: Exact copy of the challenge from step 2, echoed back.
- `signature`: Ed25519 signature over the **concatenation** of the raw
  challenge bytes and the responder's DID in UTF-8:
  `sign(private_key, challenge_bytes + responder_did.encode("utf-8"))`.
  This binds the authentication to the specific responder (phishing
  resistance).

### 4. CONFIRM (Responder → Initiator)

Sent by the responder after verifying the AUTH message. Completes the
handshake.

**Authentication-only mode** (no session key):

```json
{
  "type": "confirm",
  "identity_card": "<JSON string of responder's full identity card>",
  "status": "authenticated",
  "peer_did": "<initiator's DID>",
  "signature": "<base64url(Ed25519(confirm_payload))>"
}
```

**With session key establishment:**

```json
{
  "type": "confirm",
  "identity_card": "<JSON string of responder's full identity card>",
  "status": "ok",
  "peer_did": "<initiator's DID>",
  "responder_x25519": "<base64url(X25519_public_key_raw)>",
  "signature": "<base64url(Ed25519(confirm_payload))>"
}
```

The `signature` is computed over a canonical JSON of the confirm payload
**without** the `signature` field itself (same pattern as the identity card
self-signature).

### 5. AUTH-SESSION (Initiator → Responder, optional)

If session key establishment was initiated, the initiator sends a final
acknowledgement:

```json
{
  "type": "confirm",
  "status": "session_established",
  "initiator_x25519": "<base64url(X25519_public_key_raw)>",
  "session_digest": "<base64url(SHA256(session_key))>",
  "signature": "<base64url(Ed25519(session_payload))>"
}
```

### 6. ERROR (bidirectional)

Any party may terminate the handshake with an error:

```json
{
  "type": "error",
  "error": "Human-readable error description"
}
```

## Session Key Derivation

If both parties include X25519 public keys in their messages, a shared
session key is derived:

```
shared_secret = X25519(my_ephemeral_private, peer_ephemeral_public)
session_key  = HKDF-SHA256(shared_secret, salt=None, info="hermes-id/v1/handshake", length=32)
```

The session key is a 256-bit AES-GCM key suitable for encrypting subsequent
application traffic.

## Verification Rules

### For the Responder (on receiving AUTH):

1. Parse `identity_card` as JSON → `IdentityCard` object
2. Verify the identity card's self-signature (`verify_identity_card()`)
3. Recover the initiator's Ed25519 public key from the card
4. Verify `signature` over `challenge || responder_did` using the
   recovered public key
5. (Optional) Apply application-level verification callback

### For the Initiator (on receiving CONFIRM):

1. Parse `identity_card` as JSON → `IdentityCard` object
2. Verify the identity card's self-signature
3. Recover the responder's Ed25519 public key from the card
4. Reconstruct the confirm payload (without `signature` field)
5. Verify `signature` over the confirm payload

## Error Handling

- Any message exceeding 64 KB must be rejected
- Unknown message types must be rejected with an ERROR response
- Invalid signatures must be rejected with an ERROR response
- Sequence violations (e.g., CHALLENGE before HELLO) must be rejected
- Handshake timeout: 30 seconds from HELLO receipt

## Extensibility

To add a new signature scheme (e.g., post-quantum Dilithium):

1. Add `"dilithium-challenge-v1"` to the `protocols` list in HELLO
2. Define a new CHALLENGE format using the new signature scheme
3. The `version` field allows negotiating protocol features

The `publicKeyMultibase` field in the identity card already supports
multicodec prefixes for different key types.
