# Integration Guide — hermes-id for spacetime-x Projects

This guide explains how any spacetime-x service can authenticate agents
using hermes-id. The integration is **offline-first**: tokens are verified
locally against a cached copy of the auth server's identity card, so your
service keeps working even when the auth server is down.

Since v1.3.0 the app-side SDK provides:

- **Offline-first verification** — fetch + cache the server card once at
  startup (disk-cached in `~/.hermes/auth/`), then verify every token
  locally: Ed25519 signature, expiry, audience. No per-request round-trip.
- **Audience enforcement** — every token is scoped to a project (`aud`).
  A token minted for `spacetime-tv` is rejected by `spacetime-air` with 401.
  This is **mandatory** — `HermesIDAuth` refuses to start without a project.
- **Best-effort online revocation** — when the auth server is reachable the
  SDK asks whether a token was revoked (cached for a few minutes); when it's
  unreachable, locally-valid tokens are accepted (fail-open).
- **Every app type** — FastAPI dependency for web/API servers, plus a pure
  `verify_token_offline()` function for CLI tools, cron jobs, scripts.

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────────────┐
│  Agent       │     │  hermes-id Auth   │     │  SpaceTime-X         │
│  (Hermes)    │     │  Server (:9488)   │     │  Service (:8xxx)     │
└──────┬───────┘     └────────┬─────────┘     └──────────┬───────────┘
       │                      │                          │
       │  POST /challenge     │                          │
       ├──────────────────────►│                          │
       │◄─── challenge_b64 ───┤                          │
       │  POST /authenticate  │                          │
       │  {did, signature,    │                          │
       │   challenge_b64,     │                          │
       │   identity_card,     │                          │
       │   aud: "spacetime-tv"}                           │
       ├──────────────────────►│                          │
       │◄─── signed_token ────┤                          │
       │                      │                          │
       │  GET /api/data       │   GET /identity (once,   │
       │  Authorization:      │   then disk-cached)      │
       │  Bearer <token>      │◄─────────────────────────┤
       │  (aud=spacetime-tv)  │                          │
       ├────────────────────────────────────────────────►│
       │                      │  verify OFFLINE:         │
       │                      │  Ed25519 sig + aud + exp │
       │                      │  POST /verify (best-     │
       │                      │  effort revocation)      │
       │                      │◄─────────────────────────┤
       │                      │  {valid: true, did:..}   │
       │                      ├─────────────────────────►│
       │◄─── 200 OK + data ──────────────────────────────┤
```

## Step 1: Deploy the Auth Server

```bash
# Install from the repo (not yet published to PyPI — until it is, the
# source-tree install below is the only way to get the server extra):
git clone https://github.com/omiinaya/hermes-auth-plugin.git
cd hermes-auth-plugin
pip install '.[server]'

# Set passphrase
export HERMES_ID_PASSPHRASE="your-strong-passphrase"

# Generate an admin key
export HERMES_ID_ADMIN_KEY="$(openssl rand -base64 32)"

# Start the server
hermes-id server --host 0.0.0.0 --port 9488
```

**Output:**
```
🔐  hermes-id Auth Server v1.5.0
    Server DID:    did:hermes:wUFSjG64-BBT
    Listening:     http://0.0.0.0:9488
    API docs:      http://0.0.0.0:9488/docs
    Admin key:     X7Y8z9... (set HERMES_ID_ADMIN_KEY to customize)
```

## Step 2: Protect Your Service (FastAPI)

Add the env contract to your service (`.env` or systemd unit):

```bash
HERMES_AUTH_SERVER_URL=http://192.168.1.10:9488
HERMES_AUTH_PROJECT=spacetime-tv      # your project's audience
```

Then drop the dependency into your FastAPI app:

```python
from fastapi import Depends
from hermes_id.fastapi_middleware import HermesIDAuth

auth = HermesIDAuth()  # reads the two env vars above

@app.get("/api/protected")
async def protected_route(agent: dict = Depends(auth.verify)):
    return {"did": agent["did"]}

# Protect a whole router
router = APIRouter(dependencies=[Depends(auth.verify)])
```

That's it. Every request to `/api/protected` now requires a valid hermes-id
Bearer token whose `aud` equals `spacetime-tv`. The `agent` dict contains
`did`, `aud`, `issued_at`, `expires_at`, `token_id`.

> ⚠️ `HermesIDAuth` raises `ValueError` at startup if either env var is
> missing — audience enforcement is not optional.

## Step 3: Protect CLI Tools / Cron Jobs (no FastAPI)

```python
from hermes_id.sdk import load_server_card, verify_token_offline

card = load_server_card("http://192.168.1.10:9488")   # disk-cached
payload = verify_token_offline(token, card, project="spacetime-tv")
if payload is None:
    sys.exit("invalid or unauthorized token")
```

## Step 4: Agent Registration & Approval

Agents must register and be approved before they can authenticate.

### Agent-side (in terminal or via Hermes):

```python
from hermes_id.auth_client import AuthClient

client = AuthClient("http://192.168.1.10:9488", identity_dir="~/.hermes/identity")
card = client._storage.get_identity_card()
result = client.register_agent(card.id, display_name="My Service Agent")
print(result["status"])  # "pending"
```

### Admin-side:

```bash
hermes-id-admin --server http://192.168.1.10:9488 --admin-key KEY list --status pending
hermes-id-admin --server http://192.168.1.10:9488 --admin-key KEY approve did:hermes:abc123
```

Or via the Hermes slash command:
```
/hermes-id admin list --status pending
/hermes-id admin approve did:hermes:abc123
```

## Step 5: Agent Authenticates (scoped token)

```python
from hermes_id.auth_client import AuthFlow

flow = AuthFlow("http://192.168.1.10:9488", identity_dir="~/.hermes/identity")
# Scope the token to the project you're calling — required by audience
# enforcement on the service side.
token, result = flow.login(aud="spacetime-tv")

import httpx
r = httpx.get("http://my-service:8000/api/data",
    headers={"Authorization": f"Bearer {token}"})
```

### Persistent token cache (agents / scripts)

`hermes_id.sdk.TokenCache` stores the latest token per project at
`~/.hermes/auth-tokens/<project>.json`, so a script can present a valid
token without re-running the challenge flow every invocation:

```python
from hermes_id.sdk import TokenCache

cache = TokenCache("spacetime-tv")
token, payload = cache.get()          # None if not cached
cache.put(token, payload)             # persist after login/refresh
cache.clear()
```

## Deployment Options

### Docker

```bash
# Build the image from the repo (there is no prebuilt Docker Hub image):
docker build -t hermes-id-auth .
docker run -d \
  --name hermes-id-auth \
  -p 9488:9488 \
  -e HERMES_ID_PASSPHRASE=your-passphrase \
  -e HERMES_ID_ADMIN_KEY=your-admin-key \
  -v /path/to/identity:/app/identity \
  -v /path/to/data:/app/data \
  hermes-id-auth
```

> The image runs as an unprivileged user (`hermesid`, uid 10001) — mount
> the identity/data volumes with ownership that user can write to.

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
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9488/health', timeout=5).status == 200 else 1)"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

  my-service:
    build: ./my-service
    ports: ["8000:8000"]
    environment:
      HERMES_AUTH_SERVER_URL: http://auth:9488
      HERMES_AUTH_PROJECT: my-service
    depends_on:
      auth:
        condition: service_healthy
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
| POST | `/authenticate` | None | Prove identity → get token (accepts `aud`) |
| POST | `/verify` | None | Verify a token (returns `aud` too) |
| POST | `/token/refresh` | None | Refresh expiring token (preserves `aud`) |
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
| 401 | Unauthorized (bad signature, expired challenge/token, audience mismatch) |
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
  "purpose": "auth",
  "aud": "spacetime-tv"
}
```

Offline verification (the recommended path):
```python
from hermes_id.sdk import load_server_card, verify_token_offline

card = load_server_card("http://192.168.1.10:9488")
payload = verify_token_offline(token, card, project="spacetime-tv")
```
