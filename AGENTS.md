# hermes-id — Agent Quickstart

**Stack:** Python 3.11+ | cryptography (Ed25519, X25519, AES-256-GCM) | Hermes Plugin

## First-Time Setup

```bash
# 1. Clone and install
git clone https://github.com/omiinaya/hermes-id.git
cd hermes-id
pip install -e .

# 2. Create your identity
hermes-id init       # You'll be prompted for a passphrase

# 3. Verify
hermes-id status
hermes-id show
```

## Key Commands

| Command | Purpose |
|---------|---------|
| `hermes-id init` | Create a new identity keypair + card |
| `hermes-id status` | Show identity status |
| `hermes-id show` | Display formatted identity card |
| `hermes-id export` | Get identity card as JSON (shareable) |
| `hermes-id verify <file>` | Check an identity card's self-signature |
| `hermes-id sign <file>` | Sign a file with your private key |
| `hermes-id verify-sig <file> <sig> --identity <card>` | Verify a signature |
| `hermes-id handshake listen` | Start a handshake server (responder) |
| `hermes-id handshake connect <host:port>` | Connect for mutual auth |

## Architecture

```
┌──────────────────┐     ┌──────────────────┐
│  Hermes Agent A  │     │  Agent B / App   │
│  did:hermes:abc  │     │  did:hermes:xyz  │
│       │          │     │                  │
│  HELLO ────────► │     │                  │
│  CHALLENGE ◄──── │  ──┤                  │
│  AUTH ────────►  │     │                  │
│  CONFIRM ◄────── │     │                  │
│       │          │     │                  │
│  ✅ Mutual auth  │     │  ✅ Mutual auth  │
└──────────────────┘     └──────────────────┘
```

Each agent has:
- **Ed25519 keypair** — generated from kernel entropy
- **Identity card** — self-signed DID document (public)
- **Encrypted private key** — AES-256-GCM at rest
- **Handshake protocol** — challenge-response mutual auth
- **Optional session key** — X25519+HKDF derived after auth

## Files

- `src/hermes_id/` — Python package (CLI + library)
- `plugins/hermes-id/` — Hermes plugin (self-contained)
- `docs/ARCHITECTURE.md` — Full architectural decisions
- `docs/PROTOCOL.md` — Wire protocol specification
- `docs/THREAT_MODEL.md` — Security analysis & assumptions
