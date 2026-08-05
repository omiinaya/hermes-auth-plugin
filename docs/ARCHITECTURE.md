# hermes-id Architecture

> **Self-Sovereign Identity for Hermes Agent instances** — Ed25519-based DIDs,
> verifiable identity cards, and a secure mutual-authentication handshake protocol.

## Table of Contents

1. [Overview](#overview)
2. [Core Concepts](#core-concepts)
3. [Cryptographic Design](#cryptographic-design)
4. [Identity Card Format](#identity-card-format)
5. [Handshake Protocol](#handshake-protocol)
6. [Key Storage](#key-storage)
7. [Code Architecture](#code-architecture)
8. [Threat Model Summary](#threat-model-summary)
9. [Related Docs](#related-docs)

---

## Overview

hermes-id gives every Hermes Agent instance a **self-sovereign identity** —
analogous to a driver's license or Dominican *cédula*. The identity is:

- **Self-generated** — keys are created locally, never touch a server
- **Self-certified** — the identity card is self-signed (no CA required)
- **Peer-verifiable** — any party can check the self-signature
- **Replay-proof** — authentication uses fresh random challenges
- **Forward-secure** — optional ephemeral session keys via X25519+HKDF

## Core Concepts

| Concept | Description |
|---------|-------------|
| **DID** (Decentralized Identifier) | `did:hermes:<sha256(pubkey)[:12]>` — content-addressed, globally unique |
| **Identity Card** | Self-signed JSON-LD document carrying the DID, public key, and proof |
| **Ed25519 Keypair** | Primary identity key for signing and authentication |
| **X25519 Keypair** | Ephemeral key for session key agreement (optional) |
| **Handshake** | 4-message mutual challenge-response protocol |
| **Session Key** | AES-256-GCM key derived from X25519 ECDH after successful auth |

## Cryptographic Design

### Signing: Ed25519 (EdDSA on Curve25519)

- **Provider:** `cryptography` library (PyCA, FIPS 140-2 validated)
- **Key size:** 256-bit curve, 32-byte public key, 64-byte signature
- **Security:** SUF-CMA (strongly unforgeable under chosen-message attack)
- **Performance:** ~50k signatures/second on modern CPUs
- **Post-quantum:** Ed25519 is **not** post-quantum resistant. A CRQC could
  recover the private key from the public key. For future PQ safety, the
  protocol version field allows upgrading the signature scheme without
  breaking backwards compatibility.

### Key Encapsulation: X25519 ECDH

- **Provider:** `cryptography` library (Curve25519 RFC 7748)
- **Purpose:** Ephemeral session key agreement after handshake
- **Output:** 32-byte shared secret → HKDF-SHA256 stretched to 32-byte AES key
- **Forward secrecy:** Ephemeral X25519 keys are discarded after session end

### Encryption at Rest: AES-256-GCM

- **Provider:** `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
- **Key size:** 256 bits
- **Nonce:** 96-bit random (12 bytes)
- **Authentication tag:** 128-bit (16 bytes)
- **Additional authenticated data (AAD):** None (future: version tag)
- **Security:** AEAD (authenticated encryption with associated data) —
  provides both confidentiality and integrity. GCM is misuse-resistant:
  a repeated nonce leaks only equality of plaintexts, not the key.

### Key Derivation: Tiered KDF

| Priority | KDF | When | Strength |
|----------|-----|------|----------|
| 1 | Argon2id (argon2-cffi) | Optional pip dep installed | **Highest** — memory-hard + side-channel resistant |
| 2 | scrypt (hashlib) | Python ≥ 3.6 stdlib | High — memory-hard (N=2^17, r=8, p=1) |
| 3 | PBKDF2-SHA256 (hashlib) | Fallback if scrypt unavailable | Moderate — CPU-hard only, 600K iterations |

Argon2id configuration: 3 iterations, 64 MiB memory, 4 parallelism lanes.

Blobs record the exact KDF *and its parameters* (v3 format), so
parameter changes never invalidate existing identities. Blobs created
before v3 (v1/v2) are decrypted with pinned historical parameters
(scrypt N=2^20 — the value in effect when they were created).

## Identity Card Format

```json
{
  "@context": "https://hermes-id.proto/v1",
  "id": "did:hermes:8YgVqJpKq7B2Lm",
  "controller": "did:hermes:8YgVqJpKq7B2Lm",
  "verificationMethod": [{
    "id": "did:hermes:8YgVqJpKq7B2Lm#keys-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:hermes:8YgVqJpKq7B2Lm",
    "publicKeyMultibase": "u<base64url(public_key)>"
  }],
  "authentication": ["did:hermes:8YgVqJpKq7B2Lm#keys-1"],
  "assertionMethod": ["did:hermes:8YgVqJpKq7B2Lm#keys-1"],
  "created": "2026-07-30T12:00:00Z",
  "metadata": {
    "profile": "default"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-07-30T12:00:00Z",
    "verificationMethod": "did:hermes:8YgVqJpKq7B2Lm#keys-1",
    "proofPurpose": "assertionMethod",
    "signatureValue": "<base64url(signature)>"
  }
}
```

The card is fully self-contained. The `proof` field is the Ed25519 signature
over the canonical JSON of the card **without** the `proof` field itself.
This means any tampering with any field breaks the self-signature.

## Handshake Protocol

### Message Flow

```
Initiator (A)                          Responder (B)
─────────────                          ─────────────

1. HELLO ───────────────────────────►
   { version, from_did,
     supported_protocols[] }

2.                                ◄── CHALLENGE
    { challenge: 32 random bytes,
      from_did,
      signature: Ed25519(challenge) }

3. AUTH ───────────────────────────►
   { identity_card: {full card},
     challenge: <echoed> ,
     signature: Ed25519(challenge || B_did) }

4.                                ◄── CONFIRM
    { identity_card: {full card},
      status: "ok",
      responder_x25519: <ephemeral pubkey>,
      signature: Ed25519(confirm_payload) }

5. Session Establishment (optional):
   Both sides derive session_key = HKDF(X25519(priv, peer_pub))
```

### Security Properties

- **Replay protection:** Every handshake uses a fresh 256-bit random challenge.
  An attacker recording a previous handshake cannot replay it.
- **Mutual authentication:** Both parties prove control of their private keys.
  Step 3 proves the initiator. Step 4 proves the responder.
- **Phishing resistance:** The initiator's challenge signature in step 3
  includes the responder's DID (`challenge || B_did`), binding the proof to
  the intended responder.
- **Forward secrecy:** Ephemeral X25519 keys are generated per-handshake and
  discarded after the session. Compromising the long-term Ed25519 key does
  **not** expose past session keys.
- **No central registry:** Authentication is purely peer-to-peer. No CA, no
  blockchain, no PKI required.

## Key Storage

```
~/.hermes/identity/
├── identity.json      # Identity card (plaintext JSON, shareable)
├── private.enc        # Encrypted private key (AES-256-GCM blob)
└── storage.json       # Storage metadata (KDF params, version)
```

**private.enc** binary format (v3 — fully self-describing):

```
[4 bytes: magic "HID3"]
[1 byte:  KDF id — 0=argon2id, 1=scrypt, 2=pbkdf2]
[12 bytes: KDF parameters (big-endian u32 triple)
           argon2id: time_cost, memory_cost, parallelism
           scrypt:   n, r, p
           pbkdf2:   iterations, 0, 0]
[16 bytes: KDF salt]
[12 bytes: AES-GCM nonce]
[N  bytes: AES-GCM ciphertext + 16-byte authentication tag]
```

Legacy formats stay readable: v2 (`HID2` + KDF id, no params — uses pinned
historical parameters) and v1 (no header — KDFs tried in preference order,
validated by the GCM tag).

All files are created with `0600` (owner read/write only). The directory
is `0700`.

## Code Architecture

```
src/hermes_id/
├── __init__.py     # Public API re-exports
├── __main__.py     # python -m hermes_id
├── crypto.py       # Ed25519, X25519, AES-256-GCM, KDF, DID derivation
├── identity.py     # IdentityCard dataclass, creation, verification, formatting
├── storage.py      # IdentityStorage — encrypted file management
├── handshake.py    # HandshakeProtocol — state machine + TCP transport
└── cli.py          # argparse CLI dispatcher

plugins/hermes-id/
├── __init__.py     # Hermes plugin (self-contained, shells to CLI)
└── plugin.yaml     # Plugin metadata
```

### Dependency Graph

```
cli.py ──► identity.py ──► crypto.py
     │         │
     └──► storage.py ──► crypto.py
     │              └── identity.py
     │
     └──► handshake.py ──► crypto.py
                       └── identity.py
```

### Key Design Decisions

1. **Self-contained plugin (stdlib-only):** The Hermes plugin uses `subprocess`
   to call the `hermes-id` CLI. This keeps the plugin zero-dependency while
   the CLI uses `cryptography` for real crypto.

2. **State machine for handshake protocol:** `HandshakeProtocol` is
   transport-agnostic. TCP is provided as a convenience; WebSocket, Unix
   sockets, or HTTP can be layered on top.

3. **Optional Argon2id:** The strongest KDF is optional via `pip install
   hermes-id[argon2]`. The code auto-detects the best available.

4. **Multibase encoding:** Uses `u` prefix (base64url) for multibase instead
   of `z` (base58btc) to avoid a base58 dependency. The format is explicitly
   marked to support migration.

## Threat Model Summary

See [THREAT_MODEL.md](./THREAT_MODEL.md) for the full analysis, and
[SECURITY.md](../SECURITY.md) for how to report a vulnerability. Key
points:

| Threat | Mitigation |
|--------|-----------|
| Private key theft (disk) | AES-256-GCM + Argon2id/scrypt, 0600 perms |
| Replay attack | Fresh 256-bit challenge per handshake |
| MITM during handshake | Mutual authentication, signed challenges bound to DIDs |
| Self-signature forgery | Ed25519 SUF-CMA, card verified before trust |
| Weak passphrase | Min 8 chars, memory-hard KDF prevents offline bruteforce |
| Random number weakness | `os.urandom()` — kernel CSPRNG |

## Related Docs

- [INTEGRATION.md](./INTEGRATION.md) — deploying the HTTP **Auth Server** and
  protecting your service with hermes-id tokens (offline-first verification,
  audience enforcement, agent registry)
- [PROTOCOL.md](./PROTOCOL.md) — the mutual-auth handshake wire protocol
- [THREAT_MODEL.md](./THREAT_MODEL.md) — the security analysis
