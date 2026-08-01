"""
FastAPI middleware for hermes-id authentication (offline-first).

Drop this into any spacetime-x FastAPI service to protect routes with
hermes-id auth tokens. Built on the app-side SDK (``hermes_id.sdk``):
tokens are verified **locally** against a cached copy of the auth server's
identity card (Ed25519 signature + expiry + audience), with a best-effort
online revocation check. The auth server being down never takes your app
down.

Env contract (defaults; constructor args override)::

    HERMES_AUTH_SERVER_URL=http://192.168.1.10:9488
    HERMES_AUTH_PROJECT=spacetime-tv      # audience — tokens scoped per project

Usage::

    from hermes_id.fastapi_middleware import HermesIDAuth

    app = FastAPI()
    auth = HermesIDAuth()  # reads env; audience enforcement is mandatory

    # Protect individual routes
    @app.get("/api/protected")
    async def protected(agent: dict = Depends(auth.verify)):
        return {"did": agent["did"]}

    # Or protect all routes on a router
    router = APIRouter(dependencies=[Depends(auth.verify)])

Security notes:
- **Audience enforcement is not optional**: ``HermesIDAuth`` refuses to
  start without a project name (``HERMES_AUTH_PROJECT`` or ``project=``).
  A token minted for another project is rejected with 401.
- **Offline-first**: verification never blocks on the network. The server
  card is fetched once and cached to disk (``~/.hermes/auth/``).
- **Revocation is best-effort**: the SDK asks the auth server whether a
  token was revoked and caches the answer for a few minutes; if the server
  is unreachable, locally-valid tokens are accepted (fail-open).

The old ``require_auth`` decorator and ``get_agent_did`` header helper were
removed in v1.3.0 — the decorator was silently ignored by FastAPI (broken
auth), and ``get_agent_did`` depended on a header nothing ever set. Use
``Depends(auth.verify)`` and read ``payload["did"]``.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from hermes_id.sdk import (
    ENV_PROJECT,
    ENV_SERVER_URL,
    AuthError,
    RevocationChecker,
    default_card_cache_path,
    load_server_card,
    verify_token_offline,
)

_bearer_scheme = HTTPBearer(auto_error=False)


class HermesIDAuth:
    """FastAPI dependency for offline-first hermes-id token verification.

    Reads ``HERMES_AUTH_SERVER_URL`` and ``HERMES_AUTH_PROJECT`` from the
    environment by default (explicit constructor args override). Both are
    **required** — audience enforcement is mandatory, not optional.

    Usage as a route dependency::

        auth = HermesIDAuth()  # env-driven

        @app.get("/protected")
        async def route(auth_data: dict = Depends(auth.verify)):
            return {"did": auth_data["did"]}

    Or as a router-wide dependency::

        router = APIRouter(dependencies=[Depends(auth.verify)])
    """

    def __init__(
        self,
        server_url: str | None = None,
        project: str | None = None,
        cache_dir: str | None = None,
        card_max_age: float = 3600.0,
        revocation_ttl: float = 300.0,
        timeout: float = 5.0,
        allow_stale_card: bool = True,
        verify: bool | str = True,
    ):
        self._server_url = (server_url or os.environ.get(ENV_SERVER_URL, "")).rstrip("/")
        self._project = project or os.environ.get(ENV_PROJECT, "")
        self._cache_dir = cache_dir
        self._card_max_age = card_max_age
        self._timeout = timeout
        self._allow_stale_card = allow_stale_card
        # TLS verification: explicit arg > HERMES_AUTH_VERIFY env (path to a
        # CA bundle, or "true"/"false") > default True.
        if verify is True and os.environ.get("HERMES_AUTH_VERIFY"):
            env_verify = os.environ["HERMES_AUTH_VERIFY"].strip().lower()
            if env_verify in ("false", "0", "no"):
                verify = False
            elif env_verify in ("true", "1", "yes"):
                verify = True
            else:
                verify = env_verify  # CA bundle path
        self._verify = verify

        if not self._server_url:
            raise ValueError(
                f"{ENV_SERVER_URL} must be set (or pass server_url=) — "
                "e.g. http://192.168.1.10:9488"
            )
        if not self._project:
            raise ValueError(
                f"{ENV_PROJECT} must be set (or pass project=) — "
                "audience enforcement is mandatory; tokens are scoped per project"
            )

        self._card: dict[str, Any] | None = None
        self._card_loaded_at: float = 0.0
        self._revocation = RevocationChecker(
            self._server_url, ttl=revocation_ttl, timeout=timeout, verify=verify
        )

    # -- server card ------------------------------------------------------

    def get_server_card(self) -> dict[str, Any]:
        """Load the auth server's identity card (in-memory + disk cached)."""
        import time

        now = time.time()
        if self._card is not None and now - self._card_loaded_at < self._card_max_age:
            return self._card
        self._card = load_server_card(
            self._server_url,
            cache_path=(
                str(default_card_cache_path(self._server_url, self._cache_dir))
                if self._cache_dir
                else None
            ),
            timeout=self._timeout,
            max_age=self._card_max_age,
            allow_stale=self._allow_stale_card,
            verify=self._verify,
        )
        self._card_loaded_at = now
        return self._card

    # -- core verification ------------------------------------------------

    def verify_token(self, token: str) -> dict[str, Any]:
        """Verify a token offline-first, then best-effort online revocation.

        Returns the payload dict on success.

        Raises:
            AuthError: with a stable ``reason`` on every failure path.
        """
        card = self.get_server_card()
        payload = verify_token_offline(token, card, project=self._project)
        if payload is None:
            raise AuthError("invalid", "Token invalid, expired, or audience mismatch")

        token_id = payload.get("token_id", "")
        if self._revocation.is_revoked(token, token_id):
            raise AuthError("revoked", "Token has been revoked")

        return payload

    def check_token(self, token: str) -> dict[str, Any] | None:
        """Non-raising variant of :meth:`verify_token` — payload or None."""
        try:
            return self.verify_token(token)
        except AuthError:
            return None

    # -- FastAPI dependency ----------------------------------------------

    def verify(
        self,
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),  # noqa: B008
    ) -> dict[str, Any]:
        """FastAPI dependency: verify the ``Authorization: Bearer`` token.

        Usage: ``agent: dict = Depends(auth.verify)`` — on success the
        payload dict (with ``did``) is injected into the route. Raises
        HTTP 401 on missing/invalid/expired/revoked/mismatched-audience
        tokens.
        """
        from fastapi import HTTPException, status

        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization: Bearer <token> header",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            return self.verify_token(credentials.credentials)
        except AuthError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=e.detail or e.reason,
                headers={"WWW-Authenticate": "Bearer"},
            ) from e


__all__ = ["HermesIDAuth"]
