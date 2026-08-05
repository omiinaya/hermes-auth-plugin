# hermes-id — Self-Sovereign Identity for Hermes Agent

> **Every Hermes instance gets a unique Ed25519 keypair — like a driver's
> license for AI agents. Present your identity card to other agents and
> prove ownership via cryptographic handshake. No central registry needed.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](#)
[![Cryptography](https://img.shields.io/badge/crypto-Ed25519%20%7C%20X25519%20%7C%20AES--256--GCM-green)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](#)
[![CI](https://github.com/omiinaya/hermes-auth-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/omiinaya/hermes-auth-plugin/actions/workflows/ci.yml)

---

## Quick Start

```bash
# 1. Install
git clone https://github.com/omiinaya/hermes-auth-plugin.git
cd hermes-auth-plugin
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
| `hermes-id rotate [--note N] [--no-backup] [--force]` | Rotate the keypair (new DID + transition proof signed by old key) |
| `hermes-id status` | Show identity status |
| `hermes-id show` | Display formatted identity card |
| `hermes-id export [file]` | Export identity card as JSON (stdout or file) |
| `hermes-id verify <file>` | Verify an identity card's self-signature |
| `hermes-id sign <file>` | Sign a file with your private key |
| `hermes-id verify-sig <file> <sig> --identity <card>` | Verify a file signature |
| `hermes-id verify-sig <file> --signature <sig> --identity <card>` | Same, but avoids the leading-`-` signature pitfall (see below) |
| `hermes-id handshake listen [--port N]` | Start handshake server (responder role) |
| `hermes-id handshake connect <host:port>` | Connect to a peer for mutual auth |

> **Tip:** signatures are base64url, whose alphabet includes `-` and `_`.
> If a signature happens to start with `-`, argparse would read it as an
> option flag. The CLI auto-rewrites that case, and the `--signature`
> flag is the always-unambiguous form.

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
- **Key rotation** with transition proofs — new cards are signed by both the
  new key (self-proof) and the previous key (transition proof), so verifiers
  can confirm rotations were authorized by the previous controller
- **Optional TLS** — serve the auth server over HTTPS with `--tls-cert` / `--tls-key`

See [THREAT_MODEL.md](./docs/THREAT_MODEL.md) for the complete security analysis.

**Found a vulnerability?** Read [SECURITY.md](./SECURITY.md) — we accept
private reports and follow a 48h-acknowledgement disclosure policy. Do NOT
open a public issue for security bugs.

## Documentation

| File | Contents |
|------|----------|
| [ARCHITECTURE.md](./docs/ARCHITECTURE.md) | Full architectural decisions and design rationale |
| [PROTOCOL.md](./docs/PROTOCOL.md) | Wire protocol specification for implementers |
| [THREAT_MODEL.md](./docs/THREAT_MODEL.md) | Security analysis, assumptions, and mitigations |
| [SECURITY.md](./SECURITY.md) | Vulnerability disclosure policy and supported versions |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | How to contribute — testing, lint, coverage gates |
| [AGENTS.md](./AGENTS.md) | Quickstart for AI agent coders |
| [SKILL.md](./SKILL.md) | Hermes Agent skill definition |

## Development

```bash
# Install with all extras + dev tools (pytest-xdist for parallel tests)
pip install -e ".[all,dev]"

# Run tests (parallel with pytest-xdist)
make test

# Code quality
make lint
```

## License

MIT — see [LICENSE](./LICENSE).

---

## Auth Server — Integration for spacetime-x Projects

hermes-id now includes an **HTTP Auth Server** and **agent registry** that makes
it drop-dead simple for agents to authenticate with any spacetime-x service.

### Quick Start

```bash
# Install with all extras
pip install 'hermes-id[all]'

# Set your passphrase (if not stored yet)
export HERMES_ID_PASSPHRASE="your-passphrase"

# Start the auth server
hermes-id server --port 9488

# Serve over HTTPS (recommended for anything beyond localhost)
hermes-id server --port 9488 --tls-cert /etc/ssl/hermes-id.crt --tls-key /etc/ssl/hermes-id.key
```

### Key Rotation

```bash
# Rotate your identity keypair (new DID, transition-proofed)
hermes-id rotate --note "annual-rotation"

# Rotate non-interactively (from scripts)
hermes-id rotate --force --note "compromise-response"

# The old key is backed up to ~/.hermes/identity/rotated/<old-did>/
# unless you pass --no-backup
```

Rotation produces a new DID and a new self-signed card that also carries a
**transition proof** signed by the previous key. Verifiers can call
`verify_key_rotation(card)` to confirm the rotation was authorized by the
previous controller — this is what makes rotation safe against key theft:
an attacker who steals only the *new* key cannot forge a valid transition
from the *old* identity.

### Auth Flow — Agent Perspective

```python
from hermes_id.auth_client import AuthFlow, AuthClient

# 1. Authenticate and get a token, scoped to the target project
flow = AuthFlow("http://auth-server:9488", identity_dir="~/.hermes/identity")
token = flow.login(aud="spacetime-tv")  # aud = audience (project name)

# Present token to any spacetime-x service that enforces aud=spacetime-tv
response = my_service.call_api(token=token)
```

### Auth Flow — Service Perspective (offline-first, v1.3.0+)

```python
from hermes_id.fastapi_middleware import HermesIDAuth

# Env contract: HERMES_AUTH_SERVER_URL + HERMES_AUTH_PROJECT
auth = HermesIDAuth()

@app.get("/api/data")
async def data(agent: dict = Depends(auth.verify)):
    return {"did": agent["did"]}
```

The SDK verifies tokens **locally** (Ed25519 signature + expiry + audience)
against a disk-cached copy of the server's identity card — no per-request
round-trip, works when the auth server is down. Audience enforcement is
mandatory: a token minted for another project is rejected with 401.

For non-FastAPI code (CLI tools, cron, scripts):

```python
from hermes_id.sdk import load_server_card, verify_token_offline

card = load_server_card("http://auth-server:9488")
payload = verify_token_offline(token, card, project="spacetime-tv")
```

### Agent Registration & Approval Workflow

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│  Agent       │     │  hermes-id Auth   │     │  Admin       │
│  (Hermes)    │     │  Server           │     │  (You)       │
└──────┬───────┘     └────────┬─────────┘     └──────┬────────┘
       │                      │                       │
       │  POST /agents/register│                      │
       │  {did, identity_card} │                      │
       ├──────────────────────►│                      │
       │  "status": "pending"  │                      │
       │◄──────────────────────┤                      │
       │                      │                       │
       │                      │  POST /agents/{did}/approve
       │                      │◄──────────────────────┤
       │                      │  "status": "approved" │
       │                      ├──────────────────────►│
       │                      │                       │
       │  POST /challenge     │                       │
       ├──────────────────────►│                       │
       │◄──── challenge_b64 ──┤                       │
       │                      │                       │
       │  POST /authenticate  │                       │
       │  {did, signature,    │                       │
       │   challenge_b64,     │                       │
       │   identity_card}     │                       │
       ├──────────────────────►│                       │
       │◄─── signed_token ────┤                       │
       │                      │                       │
       │  Use token to call   │                       │
       │  any spacetime-x API │                       │
       │  via Bearer Auth     │                       │
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/identity` | Server's identity card (DID, public key) |
| `POST` | `/challenge` | Request a random challenge nonce |
| `POST` | `/authenticate` | Prove identity → get signed auth token |
| `POST` | `/verify` | Verify a signed auth token |
| `GET` | `/agents` | List all registered agents |
| `POST` | `/agents/register` | Self-register with identity card |
| `POST` | `/agents/{did}/approve` | Admin: approve an agent |
| `POST` | `/agents/{did}/deny` | Admin: deny an agent |
| `GET` | `/agents/{did}/status` | Check agent's approval status |
| `DELETE` | `/agents/{did}` | Remove agent from registry |
| `GET` | `/health` | Health check + server DID (status, did, version, uptime) |

### MCP Server

For other Hermes agents, an MCP server is available:

```bash
# Add to hermes config.yaml
# mcp_servers:
#   hermes-id:
#     command: "hermes-id"
#     args: ["mcp"]
```

Exposed MCP tools: `hermes_id_status`, `hermes_id_export`, `hermes_id_verify_card`,
`hermes_id_sign`, `hermes_id_verify_signature`, `hermes_id_verify_rotation`,
`hermes_id_auth_client`.

### Python AuthClient

```python
from hermes_id.auth_client import AuthClient

# Context manager auto-closes the HTTP client on exit
with AuthClient("http://localhost:9488", identity_dir="~/.hermes/identity") as client:
    # Check server health
    print(client.health())

    # Register this agent
    client.register_agent("did:hermes:abc", display_name="My Agent")

    # Full auth (sign challenge → get token)
    sig = client.sign_challenge(challenge_b64)
    result = client.authenticate("did:hermes:abc", challenge_b64, sig)
    token = result["token"]

    # Verify a token from another agent
    payload = client.verify_token(token)
```

### Token Format

Auth tokens are Ed25519-signed JSON payloads in the format:

```
base64url(payload) || "." || base64url(signature)
```

The payload contains `{did, issuer, issued_at, expires_at, purpose, aud}`
where `aud` is the audience (project name) the token is scoped to. Services
enforce `aud` locally against their own `HERMES_AUTH_PROJECT` via
`hermes_id.sdk.verify_token_offline()` — or, in FastAPI, via
`HermesIDAuth`.

