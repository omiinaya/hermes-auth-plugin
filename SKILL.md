---
name: hermes-id
description: "Self-Sovereign Identity for Hermes Agent — Ed25519-based decentralized identity, verifiable credential cards, and a mutual authentication handshake protocol. Every instance gets a unique DID, a signed identity card, and can prove ownership via challenge-response."
version: 1.0.0
---

# hermes-id Skill

## What

hermes-id gives this Hermes Agent instance a **self-sovereign identity** —
think "driver's license for AI agents". Each instance generates an Ed25519
keypair and packages the public key into a signed **identity card** (a
Verifiable Credential in DID-compatible format).

The identity card proves *who* the instance claims to be. The handshake
protocol proves *that the instance controls* its identity — via cryptographic
challenge-response, without any central registry or PKI.

## Prerequisites

- `hermes-id` CLI installed (`pip install -e .` from the repo root)
- `~/.hermes/identity/identity.json` + `private.enc` (created via `init`)

## Slash Commands

| Command | Description |
|---------|-------------|
| `/hermes-id status` | Show identity status (DID, key type, card validity) |
| `/hermes-id show` | Display formatted identity card |
| `/hermes-id export` | Get identity card as JSON |
| `/hermes-id init` | Instructions to create a new identity (requires terminal) |
| `/hermes-id verify <file>` | Verify an external identity card file |
| `/hermes-id connect <host:port>` | Instructions to start a handshake |
| `/hermes-id listen` | Instructions to start handshake server |
| `/hermes-id help` | Full command reference |

## Agent Usage

When you need to prove your identity to another service or agent:

1. **Check your identity** — run `/hermes-id status`
2. **Present your card** — run `/hermes-id export` to get the JSON
3. **Authenticate** — initiate a handshake with a peer service

When verifying another agent's identity:

1. Get their identity card (JSON)
2. Run `hermes-id verify <file>` to check the self-signature
3. If it's a service with handshake support, use the protocol

## Key Concepts

- **DID (Decentralized Identifier):** `did:hermes:<sha256-hash>` — content-addressed, unique per keypair
- **Identity Card:** Signed JSON containing the DID, public key, creation time, and metadata
- **Handshake:** Mutual challenge-response proving both sides control their keys
- **Session Key:** Optional ephemeral X25519-derived symmetric key after a handshake
- **No central registry:** Authentication is purely peer-to-peer

## Security Notes

- The private key is encrypted at rest with AES-256-GCM (key derived via scrypt/Argon2id)
- Ed25519 signatures are quantum-vulnerable but classically unforgeable
- Store your passphrase in a password manager — **it cannot be recovered**
- The identity card (public JSON) can be shared freely
- Always verify a peer's card before trusting their claims
- Tokens can be revoked server-side; the auth server rate-limits every
  endpoint and compares admin keys in constant time
- Found a vulnerability? Report privately per [SECURITY.md](./SECURITY.md)
