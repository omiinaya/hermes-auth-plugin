# Integration Guide — hermes-id for spacetime-x Projects

This guide explains how any spacetime-x service can authenticate agents
using hermes-id. The integration is designed to be **drop-in**: add ~5 lines
of code to your FastAPI service and you're done.

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Agent       │     │  hermes-id Auth   │     │  SpaceTime-X     │
│  (Hermes)    │     │  Server (:9488)   │     │  Service (:8xxx) │
└──────┬───────┘     └────────┬─────────┘     └────────┬─────────┘
       │                      │                        │
       │  POST /challenge     │                        │
       ├──────────────────────►│                        │
       │◄─── challenge_b64 ───┤                        │
       │                      │                        │
       │  POST /authenticate  │                        │
       │  {did, signature,    │                        │
       │   challenge_b64,     │                        │
       │   identity_card}     │                        │
       ├──────────────────────►│                        │
       │◄─── signed_token ────┤                        │
       │                      │                        │
       │  GET /api/data       │                        │
       │  Authorization:      │                        │
       │  Bearer <token>      │                        │
       ├──────────────────────────────────────────────►│
       │                      │  POST /verify (cached) │
       │                      │◄───────────────────────┤
       │                      │  {valid: true, did:..} │
       │                      ├───────────────────────►│
       │◄─── 200 OK + data ────────────────────────────┤
```

## Step 1: Deploy the Auth Server

```bash
# Install
pip install 'hermes-id[server]'

# Set passphrase
export HERMES_ID_PASSPHRASE="your-strong-passphrase"

# Generate an admin key
export HERMES_ID_ADMIN_KEY="$(openssl rand -base64 32)"

# Start the server
hermes-id server --host 0.0.0.0 --port 9488
```

**Output:**
```
🔐  hermes-id Auth Server v1.1.0
    Server DID:    did:hermes:wUFSjG64-BBT
    Listening:     http://0.0.0.0:9488
    API docs:      http://0.0.0.0:9488/docs
    Admin key:     X7Y8z9... (set HERMES_ID_ADMIN_KEY to customize)
```

## Step 2: Protect Your Service

Add two dependencies to your FastAPI app::

```python
from hermes_id.fastapi_middleware import HermesIDAuth, get_agent_did

auth = HermesIDAuth(server_url="http://auth-server:9488")

@app.get("/api/protected")
async def protected_route(agent: dict = Depends(auth.verify)):
    return {"did": agent["did"]}
```

That's it. Every request to `/api/protected` now requires a valid hermes-id
Bearer token. Use `Depends(get_agent_did)` to get the caller's DID in
downstream handlers.

## Step 3: Agent Registration & Approval

Agents must register and be approved before they can authenticate.

### Agent-side (in terminal or via Hermes):

```python
from hermes_id.auth_client import AuthClient

client = AuthClient("http://auth-server:9488", identity_dir="~/.hermes/identity")
card = client._storage.get_identity_card()
result = client.register_agent(card.id, display_name="My Service Agent")
print(result["status"])  # "pending"
```

### Admin-side:

```bash
hermes-id-admin --server http://auth-server:9488 --admin-key KEY list --status pending
hermes-id-admin --server http://auth-server:9488 --admin-key KEY approve did:hermes:abc123
```

Or via the Hermes slash command:
```
/hermes-id admin list --status pending
/hermes-id admin approve did:hermes:abc123
```

## Step 4: Agent Authenticates

```python
from hermes_id.auth_client import AuthFlow

flow = AuthFlow("http://auth-server:9488")
token, _ = flow.login()

# Use the token to call protected services
import httpx
r = httpx.get("http://my-service:8000/api/data",
    headers={"Authorization": f"Bearer {token}"})
```

## Deployment Options

### Docker

```bash
docker run -d \
  --name hermes-id-auth \
  -p 9488:9488 \
  -e HERMES_ID_PASSPHRASE=your-passphrase \
  -e HERMES_ID_ADMIN_KEY=your-admin-key \
  -v /path/to/identity:/app/identity \
  -v /path/to/data:/app/data \
  omiinaya/hermes-id:latest
```

### Docker Compose

```yaml
services:
  auth:
    build: .
    ports: ["9488:9488"]
    environment:
      HERMES_ID_PASSPHRASE: ${HERMES_ID_PASSPHRASE}
      HERMES_ID_ADMIN_KEY: ${HERMES_ID_ADMIN_KEY}
    volumes:
      - ./identity:/app/identity
      - ./data:/app/data

  my-service:
    build: ./my-service
    ports: ["8000:8000"]
    environment:
      HERMES_ID_SERVER_URL: http://auth:9488
    depends_on:
      - auth
```

### systemd

```bash
sudo cp deploy/hermes-id-auth.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hermes-id-auth
```

## API Reference

### Auth Server Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/identity` | None | Server's identity card |
| GET | `/health` | None | Health check |
| POST | `/challenge` | None | Get challenge nonce |
| POST | `/authenticate` | None | Prove identity → get token |
| POST | `/verify` | None | Verify a token |
| POST | `/token/refresh` | None | Refresh expiring token |
| POST | `/token/revoke` | None | Revoke a token |
| GET | `/agents` | Admin key | List agents (paginated, searchable) |
| POST | `/agents/register` | None | Self-register agent |
| POST | `/agents/{did}/approve` | Admin key | Approve agent |
| POST | `/agents/{did}/deny` | Admin key | Deny agent |
| GET | `/agents/{did}/status` | Admin key | Check agent status |
| DELETE | `/agents/{did}` | Admin key | Remove agent |

### Error Codes

| Code | Meaning |
|------|---------|
| 400 | Bad request (invalid DID, bad identity card) |
| 401 | Unauthorized (bad signature, expired challenge/token) |
| 403 | Forbidden (not registered, not approved) |
| 404 | Agent not found |
| 409 | Conflict (agent already registered/approved) |
| 429 | Rate limited |

## Token Format

Auth tokens are Ed25519-signed JSON payloads:

```
base64url(payload) || "." || base64url(Ed25519-signature)
```

The payload:
```json
{
  "did": "did:hermes:wUFSjG64-BBT",
  "issuer": "did:hermes:wUFSjG64-BBT",
  "issued_at": 1711843200.0,
  "expires_at": 1711929600.0,
  "token_id": "abc123def456",
  "purpose": "auth"
}
```

Use `POST /verify` to check tokens, or `hermes_id.server.verify_auth_token(token)`
for offline verification with a cached identity card.
