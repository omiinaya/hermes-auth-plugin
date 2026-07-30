"""
Example FastAPI service protected by hermes-id authentication.

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

"""

import os
import sys

# Add hermes-id to path if running from repo
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import uvicorn
from fastapi import FastAPI, Header, Depends
from pydantic import BaseModel

# Import the hermes-id auth middleware
from hermes_id.fastapi_middleware import HermesIDAuth, get_agent_did

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUTH_SERVER_URL = os.environ.get("HERMES_ID_SERVER_URL", "http://127.0.0.1:9488")

# This is the only line you need to add to protect your service
auth = HermesIDAuth(server_url=AUTH_SERVER_URL, cache_ttl=60, timeout=5)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Example Service (hermes-id protected)",
    version="1.0.0",
    description="""
    This service demonstrates how any spacetime-x project can authenticate
    agents using hermes-id. All routes except `/` and `/health` require a
    valid hermes-id auth token in the `Authorization: Bearer <token>` header.
    """,
)


@app.get("/")
def root():
    """Public route — no auth required."""
    return {
        "service": "hermes-id Example Service",
        "version": "1.0.0",
        "auth_server": AUTH_SERVER_URL,
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
    issued_at: float = 0.0
    expires_at: float = 0.0


@app.get("/api/protected", response_model=ProtectedResponse)
def protected_route(
    agent: dict = Depends(auth.verify),
):
    """🔒 This route requires a valid hermes-id auth token.

    The ``auth.verify`` dependency automatically:
    1. Extracts the ``Authorization: Bearer`` header
    2. Calls POST /verify on the hermes-id Auth Server
    3. Returns the token payload (or raises 401)

    The ``agent`` dict contains: ``did``, ``issued_at``, ``expires_at``.
    """
    return ProtectedResponse(
        message="✅ Authenticated! You have access to this protected resource.",
        agent_did=agent.get("did", "unknown"),
        issued_at=agent.get("issued_at", 0),
        expires_at=agent.get("expires_at", 0),
    )


@app.get("/api/me")
def me(
    did: str = Depends(get_agent_did),
):
    """🔒 Returns info about the authenticated agent.

    The ``get_agent_did`` dependency extracts the DID from the
    ``X-Agent-DID`` header that the middleware injects.
    """
    return {
        "did": did,
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
    print(f"   Try: curl http://127.0.0.1:{port}/api/protected")
    print(f"        (will fail — need Bearer token)")
    print(f"   Docs: http://127.0.0.1:{port}/docs")
    uvicorn.run(app, host="0.0.0.0", port=port)
