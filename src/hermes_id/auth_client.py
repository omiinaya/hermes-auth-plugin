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
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

import httpx

from hermes_id.crypto import _b64, _unb64, sign
from hermes_id.identity import IdentityCard
from hermes_id.storage import IdentityStorage


class AuthClient:
    """Client for the hermes-id Auth Server API.

    Agents use this to authenticate, register, and get tokens.
    Services use this to verify tokens.

    Args:
        server_url: Base URL of the hermes-id Auth Server (e.g. ``http://localhost:9488``).
        identity_dir: Path to the identity directory. If None, uses default.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        server_url: str,
        identity_dir: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self._server_url = server_url.rstrip("/")
        self._timeout = timeout
        self._storage = IdentityStorage(directory=identity_dir) if identity_dir else None
        self._client = httpx.Client(timeout=timeout, verify=False)

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    def get_identity(self) -> dict[str, Any]:
        """Get the auth server's identity card.

        Returns the server's DID document as a dict.
        """
        resp = self._client.get(f"{self._server_url}/identity")
        resp.raise_for_status()
        return resp.json()

    def health(self) -> dict[str, Any]:
        """Check if the auth server is running."""
        resp = self._client.get(f"{self._server_url}/health")
        resp.raise_for_status()
        return resp.json()

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

    def sign_challenge(self, challenge_b64: str) -> str:
        """Sign a challenge with the local identity's private key.

        Requires identity_dir to have been set on construction.

        Args:
            challenge_b64: The base64-encoded challenge from the server.

        Returns:
            Base64-encoded Ed25519 signature.

        Raises:
            RuntimeError: If no identity was loaded.
        """
        if not self._storage:
            raise RuntimeError("No identity configured. Pass identity_dir to AuthClient.")

        password = os.environ.get("HERMES_ID_PASSPHRASE") or ""
        if not password:
            raise RuntimeError("HERMES_ID_PASSPHRASE not set in environment.")

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
        identity_card: Optional[str] = None,
    ) -> dict[str, Any]:
        """Authenticate with the auth server.

        Presents a signed challenge and identity card. Returns a signed auth token.

        Args:
            did: The DID of the agent authenticating.
            challenge_b64: The challenge from the server.
            signature_b64: The Ed25519 signature of the challenge bytes.
            identity_card: JSON of the identity card. If None, loads from local storage.

        Returns::

            {"token": "...", "expires_at": 1234567890.0, "did": "did:hermes:..."}
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
            },
        )
        resp.raise_for_status()
        return resp.json()

    def verify_token(self, token: str) -> Optional[dict[str, Any]]:
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

    # ------------------------------------------------------------------
    # Agent Registry
    # ------------------------------------------------------------------

    def register_agent(
        self,
        did: str,
        identity_card: Optional[str] = None,
        display_name: str = "",
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Register this agent with the auth server.

        Args:
            did: The agent's DID.
            identity_card: JSON of the identity card. If None, loads from local storage.
            display_name: Human-readable name for the agent.
            metadata: Optional metadata dict.

        Returns::

            {"did": "did:hermes:...", "status": "pending", "message": "..."}
        """
        if identity_card is None:
            identity_card = self.get_identity_card_json()

        resp = self._client.post(
            f"{self._server_url}/agents/register",
            json={
                "did": did,
                "identity_card": identity_card,
                "display_name": display_name,
                "metadata": metadata or {},
            },
        )
        resp.raise_for_status()
        return resp.json()

    def get_agent_status(self, did: str) -> dict[str, Any]:
        """Check an agent's registration status."""
        resp = self._client.get(f"{self._server_url}/agents/{did}/status")
        resp.raise_for_status()
        return resp.json()

    def list_agents(self, status: Optional[str] = None) -> list[dict[str, Any]]:
        """List all agents in the registry.

        Args:
            status: Optional filter ('pending', 'approved', 'denied').

        Returns:
            List of agent dicts.
        """
        url = f"{self._server_url}/agents"
        if status:
            url += f"?status={status}"
        resp = self._client.get(url)
        resp.raise_for_status()
        data = resp.json()
        return data.get("agents", [])

    def approve_agent(self, did: str) -> dict[str, Any]:
        """Approve a pending agent (admin action)."""
        resp = self._client.post(f"{self._server_url}/agents/{did}/approve")
        resp.raise_for_status()
        return resp.json()

    def deny_agent(self, did: str) -> dict[str, Any]:
        """Deny a pending agent (admin action)."""
        resp = self._client.post(f"{self._server_url}/agents/{did}/deny")
        resp.raise_for_status()
        return resp.json()

    def delete_agent(self, did: str) -> dict[str, Any]:
        """Remove an agent from the registry."""
        resp = self._client.delete(f"{self._server_url}/agents/{did}")
        resp.raise_for_status()
        return resp.json()


class AuthFlow:
    """High-level convenience for the full auth flow.

    Wraps the common pattern: challenge → sign → authenticate → token.

    Usage::

        flow = AuthFlow("http://auth-server:9488", identity_dir="~/.hermes/identity")
        token = flow.login()
        # token is now a signed auth token you can present to any spacetime-x service
    """

    def __init__(self, server_url: str, identity_dir: Optional[str] = None):
        self._client = AuthClient(server_url, identity_dir=identity_dir)
        self._storage = IdentityStorage(directory=identity_dir) if identity_dir else None

    def login(self) -> str:
        """Full auth flow: challenge → sign → authenticate → return token."""
        card = self._storage.get_identity_card()
        did = card.id

        challenge = self._client.challenge(did)
        sig = self._client.sign_challenge(challenge["challenge_b64"])
        result = self._client.authenticate(did, challenge["challenge_b64"], sig)
        return result["token"]

    def close(self) -> None:
        self._client.close()
