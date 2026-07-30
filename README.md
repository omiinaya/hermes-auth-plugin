# hermes-id — Self-Sovereign Identity for Hermes Agent

> **Every Hermes instance gets a unique Ed25519 keypair — like a driver's
> license for AI agents. Present your identity card to other agents and
> prove ownership via cryptographic handshake. No central registry needed.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](#)
[![Cryptography](https://img.shields.io/badge/crypto-Ed25519%20%7C%20X25519%20%7C%20AES--256--GCM-green)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](#)

---

## Quick Start

```bash
# 1. Install
git clone https://github.com/omiinaya/hermes-id.git
cd hermes-id
pip install -e .

# 2. Create your identity (you'll be prompted for a passphrase)
hermes-id init

# 3. Verify
hermes-id status
hermes-id show
```

## What is hermes-id?

hermes-id gives this Hermes Agent instance a **cryptographically verifiable
identity** — the same way a US driver's license or a Dominican *cédula*
proves who you are. It has three capabilities:

### 1️⃣ Identification — "Who are you?"

Each instance generates an **Ed25519 keypair** at initialization. The public
key is packaged into a self-signed **identity card** (a JSON document in
DID-compatible format). The card carries:

- A globally unique **Decentralized Identifier (DID)**: `did:hermes:8YgVq...`
- The instance's **Ed25519 public key**
- A **self-signature** proving the card was created by the key's owner
- **Metadata** (profile name, creation time, etc.)

Show your card to anyone: `hermes-id export`

### 2️⃣ Authentication — "Prove it!"

Presenting a card isn't enough — you must prove you control the private key.
The **handshake protocol** uses a cryptographic challenge-response:

```
You:  "I am did:hermes:abc. Here's my card."
Peer: "Prove it. Sign this random challenge: 4f8a...c3"
You:  "Done. Here's the signature: 7b2e...1f"
Peer: "✅ Verified. You're did:hermes:abc."
```

Mutual authentication (both sides prove their identity) is supported.

### 3️⃣ Authorization — "What can you access?"

After mutual authentication, both parties optionally derive an ephemeral
**session key** (via X25519 ECDH + HKDF) for encrypting subsequent
communication. Applications can use the verified DID as an identity claim
in an access control system.

## Why hermes-id?

| Problem | Solution |
|---------|----------|
| Agents need a unique identity | Ed25519 keypair + content-addressed DID |
| No central registry exists | Self-sovereign — keys generated locally, cards self-signed |
| Replay attacks | Fresh 256-bit random challenge per handshake |
| Man-in-the-Middle | Mutual authentication with DID-bound signatures |
| Storage security | AES-256-GCM + scrypt/Argon2id at rest |
| Forward secrecy | Ephemeral X25519 session keys |

## CLI Reference

| Command | Description |
|---------|-------------|
| `hermes-id init` | Create a new identity (generates keypair, saves encrypted) |
| `hermes-id status` | Show identity status |
| `hermes-id show` | Display formatted identity card |
| `hermes-id export [file]` | Export identity card as JSON (stdout or file) |
| `hermes-id verify <file>` | Verify an identity card's self-signature |
| `hermes-id sign <file>` | Sign a file with your private key |
| `hermes-id verify-sig <file> <sig> --identity <card>` | Verify a file signature |
| `hermes-id handshake listen [--port N]` | Start handshake server (responder role) |
| `hermes-id handshake connect <host:port>` | Connect to a peer for mutual auth |

## Hermes Plugin

hermes-id ships with a Hermes Agent plugin. After installation:

```bash
# Install the plugin
mkdir -p ~/.hermes/plugins/hermes-id
cp plugins/hermes-id/* ~/.hermes/plugins/hermes-id/
hermes plugins enable hermes-id

# Or via symlink (development)
make plugin-symlink

# Restart gateway
hermes gateway restart
```

Then in any Hermes session, use:

- `/hermes-id status` — show identity status
- `/hermes-id show` — display identity card
- `/hermes-id export` — get card as JSON
- `/hermes-id help` — full reference

## Architecture

```
┌─────────────────────────────────────────────┐
│              Hermes Agent Instance            │
│  ┌─────────────────────────────────────────┐ │
│  │          hermes-id (CLI + Library)       │ │
│  │  ┌──────────┐ ┌──────────┐ ┌─────────┐ │ │
│  │  │ Identity │ │ Storage  │ │Handshake│ │ │
│  │  │  Card    │ │ (AES-256 │ │Protocol │ │ │
│  │  │ (Signed) │ │  + KDF)  │ │Ed25519  │ │ │
│  │  └────┬─────┘ └────┬─────┘ └────┬────┘ │ │
│  │       └────────────┼─────────────┘      │ │
│  │                    │                     │ │
│  │              ┌─────┴──────┐              │ │
│  │              │   Crypto   │              │ │
│  │              │ (Ed25519,  │              │ │
│  │              │ X25519,    │              │ │
│  │              │ AES-GCM)   │              │ │
│  │              └────────────┘              │ │
│  └─────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────┐ │
│  │         Hermes Plugin                   │ │
│  │  /hermes-id status | show | export ...  │ │
│  └─────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
```

## Security

Designed with **"as secure as possible"** as the primary constraint:

- **Ed25519** for signing (SUF-CMA, constant-time, 128-bit security level)
- **X25519** for ephemeral key agreement (forward secrecy)
- **AES-256-GCM** for key encryption at rest (authenticated encryption)
- **Argon2id** (preferred) / **scrypt** / **PBKDF2** for key derivation
- All randomness from **kernel CSPRNG** (`os.urandom()`)
- File permissions locked to **0600/0700**

See [THREAT_MODEL.md](./docs/THREAT_MODEL.md) for the complete security analysis.

## Documentation

| File | Contents |
|------|----------|
| [ARCHITECTURE.md](./docs/ARCHITECTURE.md) | Full architectural decisions and design rationale |
| [PROTOCOL.md](./docs/PROTOCOL.md) | Wire protocol specification for implementers |
| [THREAT_MODEL.md](./docs/THREAT_MODEL.md) | Security analysis, assumptions, and mitigations |
| [AGENTS.md](./AGENTS.md) | Quickstart for AI agent coders |
| [SKILL.md](./SKILL.md) | Hermes Agent skill definition |

## Development

```bash
# Install with all extras
pip install -e ".[all]"

# Run tests
make test

# Code quality
make lint
```

## License

MIT
