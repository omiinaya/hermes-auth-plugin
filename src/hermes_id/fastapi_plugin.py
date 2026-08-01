"""
FastAPI plugin — drop-in agent authentication for any spacetime-x service.

The quickest way to give a service hermes-id agent authentication: mount a
ready-made router that exposes agent-facing endpoints backed by
``HermesIDAuth`` (offline-first verification + audience enforcement).

Usage (3 lines in any FastAPI app)::

    from hermes_id.fastapi_plugin import install_agent_auth

    app = FastAPI(...)
    install_agent_auth(app)   # reads HERMES_AUTH_SERVER_URL + HERMES_AUTH_PROJECT

This mounts::

    GET /hermes-id/agent/me      — requires a valid Bearer token (aud must
                                   match this project); returns the token
                                   payload (did, aud, expiry).
    GET /hermes-id/agent/status  — public; reports whether the integration
                                   is configured, the auth server URL, this
                                   project's audience, and the cached server
                                   card status (offline capability).

Mounting this router does NOT protect your existing routes — they keep
their current auth. Use ``Depends(auth.verify)`` on specific routes (or
``dependencies=[Depends(auth.verify)]`` on a router) to protect them with
hermes-id tokens.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, FastAPI

from hermes_id.fastapi_middleware import HermesIDAuth

DEFAULT_PREFIX = "/hermes-id"


def install_agent_auth(
    app: FastAPI,
    prefix: str = DEFAULT_PREFIX,
    auth: HermesIDAuth | None = None,
) -> HermesIDAuth:
    """Mount the agent-auth router onto *app*.

    Args:
        app: The FastAPI application.
        prefix: URL prefix (default ``/hermes-id``).
        auth: An existing ``HermesIDAuth`` instance (env-driven by default).

    Returns:
        The ``HermesIDAuth`` instance (useful for protecting other routes
        with ``Depends(auth.verify)``).
    """
    auth = auth or HermesIDAuth()
    router = build_agent_router(auth)
    app.include_router(router, prefix=prefix)
    return auth


def build_agent_router(auth: HermesIDAuth) -> APIRouter:
    """Build the agent-auth APIRouter backed by *auth*."""
    router = APIRouter(tags=["hermes-id"])

    @router.get("/agent/me")
    def agent_me(agent: dict[str, Any] = Depends(auth.verify)) -> dict[str, Any]:  # noqa: B008 — FastAPI idiom
        """Return the authenticated agent's token payload.

        Requires ``Authorization: Bearer <token>`` where the token's ``aud``
        matches this project (HERMES_AUTH_PROJECT).
        """
        return {
            "did": agent.get("did", ""),
            "aud": agent.get("aud", ""),
            "issued_at": agent.get("issued_at", 0),
            "expires_at": agent.get("expires_at", 0),
            "authenticated": True,
        }

    @router.get("/agent/status")
    def agent_status() -> dict[str, Any]:
        """Public integration status (no auth required)."""
        card_ok = False
        card_did = ""
        try:
            card = auth.get_server_card()
            card_ok = True
            card_did = card.get("id", "")
        except Exception:
            card_ok = False
        return {
            "configured": True,
            "auth_server_url": auth._server_url,
            "project": auth._project,
            "server_card_cached": card_ok,
            "server_did": card_did,
        }

    return router


# Re-export the auth class so callers can do:
#   from hermes_id.fastapi_plugin import HermesIDAuth, install_agent_auth
__all__ = ["HermesIDAuth", "install_agent_auth", "build_agent_router"]
