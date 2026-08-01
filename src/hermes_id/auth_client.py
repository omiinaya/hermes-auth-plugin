"""
hermes-id Auth Client — lightweight Python client for integrating apps
with the hermes-id Auth Server.

Usage::

    # For agents authenticating:
    client = AuthClient("http://auth-server:9488", identity_dir="~/.hermes/identity")

    # Check server identity
    server_card = client.get_identity()

    # Request a challenge
    challenge = client.challenge("did:hermes:abc123")

    # Sign it (uses local identity)
    signature = client.sign_challenge(challenge["challenge_b64"])

    # Authenticate — returns a signed token
    result = client.authenticate(
        did="did:hermes:abc123",
        challenge_b64=challenge["challenge_b64"],
        signature_b64=signature,
    )
    token = result["token"]

    # Register
    client.register_agent(did, identity_card_json)

    # For services verifying tokens:
    payload = client.verify_token(token)
    if payload:
        print(f"Authenticated as {payload['did']}")

    # For admin operations:
    client = AuthClient("http://auth-server:9488", admin_key="your-admin-key")
    client.approve_agent(did)
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from hermes_id.crypto import _b64, _unb64, sign
from hermes_id.storage import IdentityStorage


class AuthClient:
    """Client for the hermes-id Auth Server API.

    Agents use this to authenticate, register, and get tokens.
    Services use this to verify tokens.
    Admins use this with an ``admin_key`` to manage the agent registry.

    Args:
        server_url: Base URL of the hermes-id Auth Server.
        identity_dir: Path to identity dir. If None, no local identity ops.
        timeout: HTTP request timeout in seconds.
        admin_key: Admin API key for approved/deny/delete operations.
            Can also be set via ``HERMES_ID_ADMIN_KEY`` env var.
    """

    def __init__(
        self,
        server_url: str,
        identity_dir: str | None = None,
        timeout: float = 30.0,
        admin_key: str | None = None,
    ):
        self._server_url = server_url.rstrip("/")
        self._timeout = timeout
        self._storage = IdentityStorage(directory=identity_dir) if identity_dir else None
        self._admin_key = admin_key or os.environ.get("HERMES_ID_ADMIN_KEY", "")
        self._client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    def get_identity(self) -> dict[str, Any]:
        """Get the auth server's identity card (DID document)."""
        resp = self._client.get(f"{self._server_url}/identity")
        resp.raise_for_status()
        return resp.json()

    def health(self) -> dict[str, Any]:
        """Check if the auth server is running."""
        resp = self._client.get(f"{self._server_url}/health")
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Admin headers
    # ------------------------------------------------------------------

    def _admin_headers(self) -> dict[str, str]:
        return {"X-Admin-Key": self._admin_key} if self._admin_key else {}

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def challenge(self, did: str) -> dict[str, Any]:
        """Request a challenge nonce for a DID.

        Returns::

            {"challenge_b64": "...", "expires_at": 1234567890.0, "server_did": "did:hermes:..."}
        """
        resp = self._client.post(
            f"{self._server_url}/challenge",
            json={"did": did},
        )
        resp.raise_for_status()
        return resp.json()

    def sign_challenge(self, challenge_b64: str, password: str | None = None) -> str:
        """Sign a challenge with the local identity's private key.

        Args:
            challenge_b64: The base64-encoded challenge from the server.
            password: Optional passphrase override. If None, reads from
                ``HERMES_ID_PASSPHRASE`` environment variable.

        Returns:
            Base64-encoded Ed25519 signature.
        """
        if not self._storage:
            raise RuntimeError("No identity configured. Pass identity_dir to AuthClient.")

        if not password:
            password = os.environ.get("HERMES_ID_PASSPHRASE") or ""
        if not password:
            raise RuntimeError("HERMES_ID_PASSPHRASE not set in environment or password arg not provided.")

        challenge = _unb64(challenge_b64)
        with self._storage.use_key(password) as private_key:
            sig = sign(private_key, challenge)
        return _b64(sig)

    def get_identity_card_json(self) -> str:
        """Get the local identity card as a JSON string."""
        if not self._storage:
            raise RuntimeError("No identity configured. Pass identity_dir to AuthClient.")
        card = self._storage.get_identity_card()
        return card.to_json()

    def authenticate(
        self,
        did: str,
        challenge_b64: str,
        signature_b64: str,
        identity_card: str | None = None,
        aud: str | None = None,
    ) -> dict[str, Any]:
        """Authenticate with the auth server.

        Presents a signed challenge and identity card. Returns a signed auth token.

        Args:
            did: The DID of the agent authenticating.
            challenge_b64: The challenge from the server.
            signature_b64: The Ed25519 signature of the challenge bytes.
            identity_card: JSON of the identity card. If None, loads from local storage.
            aud: Audience (project name) to scope the token to. Verifying
                services reject tokens whose ``aud`` does not match their own
                project name. Defaults to "" (unscoped).

        Returns::

            {"token": "...", "token_id": "...", "expires_at": 1234567890.0, "did": "...", "aud": "..."}
        """
        if identity_card is None:
            identity_card = self.get_identity_card_json()

        resp = self._client.post(
            f"{self._server_url}/authenticate",
            json={
                "did": did,
                "challenge_b64": challenge_b64,
                "signature_b64": signature_b64,
                "identity_card": identity_card,
                "aud": aud or "",
            },
        )
        resp.raise_for_status()
        return resp.json()

    def verify_token(self, token: str) -> dict[str, Any] | None:
        """Verify a signed auth token with the auth server.

        Args:
            token: The signed auth token string.

        Returns:
            The payload dict if valid, None otherwise.
        """
        resp = self._client.post(
            f"{self._server_url}/verify",
            json={"token": token},
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("valid"):
            return data
        return None

    def refresh_token(self, token: str) -> dict[str, Any] | None:
        """Refresh an expiring token.

        Returns a new token with extended TTL.
        """
        resp = self._client.post(
            f"{self._server_url}/token/refresh",
            json={"token": token},
        )
        if resp.status_code == 401:
            return None
        resp.raise_for_status()
        return resp.json()

    def revoke_token(self, token: str) -> bool:
        """Revoke a token before it expires.

        Returns True on success.
        """
        resp = self._client.post(
            f"{self._server_url}/token/revoke",
            json={"token": token},
        )
        resp.raise_for_status()
        return resp.json().get("status") == "revoked"

    # ------------------------------------------------------------------
    # Agent Registry
    # ------------------------------------------------------------------

    def register_agent(
        self,
        did: str,
        identity_card: str | None = None,
        display_name: str = "",
        projects: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Register this agent with the auth server.

        Args:
            did: The agent's DID.
            identity_card: JSON of the identity card. If None, loads from local storage.
            display_name: Human-readable name for the agent.
            projects: Requested project audiences this agent wants access to.
                Approvers filter by these; scoped admin keys enforce them.
            metadata: Optional metadata dict.

        Returns::

            {"did": "did:hermes:...", "status": "pending", "projects": [...], "message": "..."}
        """
        if identity_card is None:
            identity_card = self.get_identity_card_json()

        resp = self._client.post(
            f"{self._server_url}/agents/register",
            json={
                "did": did,
                "identity_card": identity_card,
                "display_name": display_name,
                "projects": projects or [],
                "metadata": metadata or {},
            },
        )
        resp.raise_for_status()
        return resp.json()

    def get_agent_status(self, did: str) -> dict[str, Any]:
        """Check an agent's registration status. Requires admin key."""
        resp = self._client.get(
            f"{self._server_url}/agents/{did}/status",
            headers=self._admin_headers(),
        )
        resp.raise_for_status()
        return resp.json()

    def list_agents(
        self,
        status: str | None = None,
        page: int = 1,
        page_size: int = 50,
        search: str | None = None,
        project: str | None = None,
    ) -> dict[str, Any]:
        """List all agents in the registry. Requires admin key.

        Args:
            status: Optional filter ('pending', 'approved', 'denied').
            page: Page number (1-indexed).
            page_size: Items per page (max 200).
            search: Search DIDs and display names.
            project: Filter by requested project (audience).

        Returns::

            {"agents": [...], "total": N, "page": 1, "page_size": 50, "pages": N}
        """
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if status:
            params["status"] = status
        if search:
            params["search"] = search
        if project:
            params["project"] = project

        resp = self._client.get(
            f"{self._server_url}/agents",
            params=params,
            headers=self._admin_headers(),
        )
        resp.raise_for_status()
        return resp.json()

    def approve_agent(self, did: str, project: str | None = None) -> dict[str, Any]:
        """Approve a pending agent. Requires admin key.

        Args:
            did: Agent DID to approve.
            project: If set, require the agent to have requested this project
                (server enforces). Useful with ``--for <project>`` in the CLI.
        """
        params = {"project": project} if project else None
        resp = self._client.post(
            f"{self._server_url}/agents/{did}/approve",
            params=params,
            headers=self._admin_headers(),
        )
        resp.raise_for_status()
        return resp.json()

    def deny_agent(self, did: str, project: str | None = None) -> dict[str, Any]:
        """Deny a pending agent. Requires admin key.

        Args:
            did: Agent DID to deny.
            project: If set, require the agent to have requested this project
                (server enforces).
        """
        params = {"project": project} if project else None
        resp = self._client.post(
            f"{self._server_url}/agents/{did}/deny",
            params=params,
            headers=self._admin_headers(),
        )
        resp.raise_for_status()
        return resp.json()

    def delete_agent(self, did: str) -> dict[str, Any]:
        """Remove an agent from the registry. Requires admin key."""
        resp = self._client.delete(
            f"{self._server_url}/agents/{did}",
            headers=self._admin_headers(),
        )
        resp.raise_for_status()
        return resp.json()


class AuthFlow:
    """High-level convenience for the full auth flow.

    Wraps the common pattern: challenge → sign → authenticate → token.

    Usage::

        flow = AuthFlow("http://auth-server:9488", identity_dir="~/.hermes/identity")
        token = flow.login()
    """

    def __init__(self, server_url: str, identity_dir: str | None = None):
        self._client = AuthClient(server_url, identity_dir=identity_dir)
        self._storage = IdentityStorage(directory=identity_dir) if identity_dir else None

    def login(self, aud: str | None = None) -> tuple[str, dict[str, Any]]:
        """Full auth flow: challenge → sign → authenticate → return token.

        Args:
            aud: Audience (project name) to scope the token to. When set, the
                returned token only verifies on services whose project name
                matches. Recommended for every integration.

        Returns:
            Tuple of (token_string, full_response_dict).
        """
        card = self._storage.get_identity_card()
        did = card.id

        challenge = self._client.challenge(did)
        sig = self._client.sign_challenge(challenge["challenge_b64"])
        result = self._client.authenticate(did, challenge["challenge_b64"], sig, aud=aud)
        return result["token"], result

    def close(self) -> None:
        self._client.close()
