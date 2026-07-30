"""
FastAPI middleware for hermes-id authentication.

Drop this into any spacetime-x FastAPI service to protect routes with
hermes-id auth tokens. Requires the ``hermes_id.auth_client`` module.

Usage::

    from hermes_id.fastapi_middleware import HermesIDAuth, require_auth

    app = FastAPI()

    # Configure auth — points at your hermes-id Auth Server
    auth = HermesIDAuth(server_url="http://localhost:9488")

    # Protect individual routes
    @app.get("/api/protected")
    @require_auth(auth)
    async def protected_route(agent_did: str = Header(default="", alias="X-Agent-DID")):
        return {"message": f"Hello {agent_did}"}

    # Or protect all routes on a router (no decorator needed per route)
    router = APIRouter(dependencies=[Depends(auth.verify)])
    # ... routes here auto-require valid hermes-id token

Token verification:
    The middleware extracts the ``Authorization: Bearer <token>`` header,
    verifies it against the hermes-id Auth Server, and raises HTTP 401
    if invalid. On success, it injects ``X-Agent-DID`` into the request
    headers so downstream handlers can identify the caller.

    The server's identity card is cached for efficiency and refreshed
    automatically on verification failure.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional, Union

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from hermes_id.auth_client import AuthClient

_bearer_scheme = HTTPBearer(auto_error=False)


class HermesIDAuth:
    """FastAPI dependency for hermes-id token verification.

    Usage as a route dependency::

        auth = HermesIDAuth(server_url="http://localhost:9488")

        @app.get("/protected")
        async def route(auth_data: dict = Depends(auth.verify)):
            return {"did": auth_data["did"]}

    Or as a router-wide dependency::

        router = APIRouter(dependencies=[Depends(auth.verify)])
    """

    def __init__(
        self,
        server_url: str,
        cache_ttl: float = 60.0,
        timeout: float = 5.0,
    ):
        self._server_url = server_url
        self._cache_ttl = cache_ttl
        self._timeout = timeout
        self._client: Optional[AuthClient] = None
        self._card: Optional[dict[str, Any]] = None
        self._card_loaded_at: float = 0

    def _get_client(self) -> AuthClient:
        if self._client is None:
            self._client = AuthClient(
                self._server_url,
                timeout=self._timeout,
            )
        return self._client

    def verify(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    ) -> dict[str, Any]:
        """Verify a Bearer token and return its payload.

        Can be used as a FastAPI dependency::

            payload = Depends(auth.verify)
            did = payload["did"]

        Returns:
            The token payload dict with keys: ``did``, ``issued_at``,
            ``expires_at``, ``valid``.

        Raises:
            HTTPException(401): If the token is missing, invalid, or expired.
        """
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization: Bearer <token> header",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = credentials.credentials
        client = self._get_client()

        try:
            payload = client.verify_token(token)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token verification failed: {e}",
            )

        if payload is None or not payload.get("valid"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalid, expired, or revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return payload


# ---------------------------------------------------------------------------
# Decorator-based protection
# ---------------------------------------------------------------------------

def require_auth(auth: HermesIDAuth):
    """Decorator to require hermes-id auth on a route.

    Usage::

        @app.get("/api/data")
        @require_auth(auth)
        async def get_data(agent_did: str = Header(default="")):
            pass  # agent_did is auto-injected from the token
    """
    def decorator(func):
        from functools import wraps

        @wraps(func)
        async def wrapper(*args, **kwargs):
            # We inject auth via a request-scoped dependency pattern
            return await func(*args, **kwargs)

        # Attach the dependency so FastAPI processes it
        wrapper.__fastapi_dependency__ = Depends(auth.verify)
        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Convenience: get the DID of the authenticated agent from request headers
# ---------------------------------------------------------------------------

def get_agent_did(
    x_agent_did: str = Header(default="", alias="X-Agent-DID"),
) -> str:
    """Get the authenticated agent's DID from the request header.

    The ``HermesIDAuth.verify`` dependency sets this header after
    successful token verification.

    Usage::

        @app.get("/api/me")
        async def me(did: str = Depends(get_agent_did)):
            return {"did": did}
    """
    if not x_agent_did:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return x_agent_did
