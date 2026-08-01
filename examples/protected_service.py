"""
Example FastAPI service protected by hermes-id authentication (offline-first).

This demonstrates how any spacetime-x service can integrate with
the hermes-id Auth Server to authenticate agents.

Run::

    # 1. Start the hermes-id auth server (separate terminal)
    hermes-id server --port 9488

    # 2. Run this example service
    pip install 'hermes-id[server]'
    python examples/protected_service.py

    # 3. As an agent, get a token and call the API
    python examples/agent_client.py

Env contract (v1.3.0+):
    HERMES_AUTH_SERVER_URL=http://127.0.0.1:9488
    HERMES_AUTH_PROJECT=demo-service
"""

import os
import sys

# Add hermes-id to path if running from repo
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import uvicorn
from fastapi import Depends, FastAPI
from pydantic import BaseModel

# Import the hermes-id auth middleware (offline-first, audience-enforced)
from hermes_id.fastapi_middleware import HermesIDAuth

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUTH_SERVER_URL = os.environ.get("HERMES_AUTH_SERVER_URL", "http://127.0.0.1:9488")
AUTH_PROJECT = os.environ.get("HERMES_AUTH_PROJECT", "demo-service")

# This is the only line you need to add to protect your service.
# Reads HERMES_AUTH_SERVER_URL / HERMES_AUTH_PROJECT from env by default;
# audience enforcement is mandatory (tokens scoped per project).
auth = HermesIDAuth(server_url=AUTH_SERVER_URL, project=AUTH_PROJECT)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Example Service (hermes-id protected)",
    version="1.3.0",
    description="""
    This service demonstrates how any spacetime-x project can authenticate
    agents using hermes-id. All routes except `/` and `/health` require a
    valid hermes-id auth token in the `Authorization: Bearer <token>` header.
    Verification is offline-first (cached server card); tokens must carry
    `aud=demo-service`.
    """,
)


@app.get("/")
def root():
    """Public route — no auth required."""
    return {
        "service": "hermes-id Example Service",
        "version": "1.3.0",
        "auth_server": AUTH_SERVER_URL,
        "auth_project": AUTH_PROJECT,
        "docs": "/docs",
    }


@app.get("/health")
def health():
    """Public health check."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Protected routes
# ---------------------------------------------------------------------------


class ProtectedResponse(BaseModel):
    message: str
    agent_did: str
    aud: str = ""
    issued_at: float = 0.0
    expires_at: float = 0.0


@app.get("/api/protected", response_model=ProtectedResponse)
def protected_route(
    agent: dict = Depends(auth.verify),
):
    """🔒 This route requires a valid hermes-id auth token.

    The ``auth.verify`` dependency automatically:
    1. Extracts the ``Authorization: Bearer`` header
    2. Verifies it offline (Ed25519 signature + expiry + audience)
    3. Does a best-effort online revocation check
    4. Returns the token payload (or raises 401)

    The ``agent`` dict contains: ``did``, ``aud``, ``issued_at``, ``expires_at``.
    """
    return ProtectedResponse(
        message="✅ Authenticated! You have access to this protected resource.",
        agent_did=agent.get("did", "unknown"),
        aud=agent.get("aud", ""),
        issued_at=agent.get("issued_at", 0),
        expires_at=agent.get("expires_at", 0),
    )


@app.get("/api/me")
def me(
    agent: dict = Depends(auth.verify),
):
    """🔒 Returns info about the authenticated agent."""
    return {
        "did": agent.get("did", ""),
        "aud": agent.get("aud", ""),
        "authenticated": True,
        "hint": "Present this DID to the admin for registration approval.",
    }


@app.get("/api/admin")
def admin_panel(
    agent: dict = Depends(auth.verify),
):
    """🔒 Example admin-only route.

    Checks the agent's DID against a hardcoded admin list.
    In production, check against the hermes-id agent registry instead.
    """
    did = agent.get("did", "")

    # Check against admin registry (in production, call the auth server)
    admin_dids = os.environ.get("ADMIN_DIDS", "").split(",")
    if did and admin_dids and did not in admin_dids:
        from fastapi import HTTPException

        raise HTTPException(403, f"Agent {did} is not an admin")

    return {
        "message": "🔐 Admin access granted.",
        "agent_did": did,
        "admin": True,
    }


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"🔐 Example protected service starting on :{port}")
    print(f"   Auth server: {AUTH_SERVER_URL}")
    print(f"   Auth project: {AUTH_PROJECT}")
    print(f"   Try: curl http://127.0.0.1:{port}/api/protected")
    print(f"        (will fail — need Bearer token)")
    print(f"   Docs: http://127.0.0.1:{port}/docs")
    uvicorn.run(app, host="0.0.0.0", port=port)
