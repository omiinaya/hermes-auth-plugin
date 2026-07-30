"""
hermes-id Auth Server — HTTP API for agent identity verification & authorization.

Provides challenge-response authentication, Ed25519-signed auth tokens,
and a SQLite-backed agent registry with an approval workflow.

Endpoints
---------

  Identity
    GET  /identity          → Server's identity card (public)

  Authentication
    POST /challenge         → Generate a random challenge nonce
    POST /authenticate      → Prove identity via signature → get signed token
    POST /verify            → Verify a signed auth token

  Agent Registry (admin)
    GET    /agents                      → List all registered agents
    POST   /agents/register             → Self-register with identity card
    POST   /agents/{did}/approve        → Admin approves agent
    POST   /agents/{did}/deny           → Admin denies agent
    GET    /agents/{did}/status         → Check agent approval status
    DELETE /agents/{did}                → Remove agent from registry

Authorization Flow
------------------
  1. Agent calls GET /identity to get the server's identity card
  2. Agent calls POST /challenge with their DID → gets a random nonce
  3. Agent signs the nonce with their Ed25519 key
  4. Agent calls POST /authenticate with DID + nonce + signature
     → Server verifies the signature against the agent's identity card
     → Server returns a signed auth token (Ed25519-signed JSON)
  5. Agent presents the token to any spacetime-x service
  6. Service calls POST /verify to check the token
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from hermes_id.crypto import (
    _b64,
    _unb64,
    generate_challenge,
    public_key_bytes,
    sign,
    verify,
)
from hermes_id.identity import (
    IdentityCard,
    verify_identity_card,
)
from hermes_id.storage import IdentityStorage

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_PORT = 9488      # one up from the handshake port (9487)
_DEFAULT_HOST = "0.0.0.0"
_TOKEN_TTL = 3600 * 24    # 24 hours default token lifetime
_CHALLENGE_TTL = 300       # 5 minutes for challenge nonces

_AGENT_REGISTRY_DB = "agent_registry.db"

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class ChallengeRequest(BaseModel):
    did: str

class ChallengeResponse(BaseModel):
    challenge_b64: str
    expires_at: float
    server_did: str

class AuthenticateRequest(BaseModel):
    did: str
    challenge_b64: str
    signature_b64: str
    identity_card: str  # JSON-encoded identity card for this DID

class AuthTokenData(BaseModel):
    did: str
    issuer: str
    issued_at: float
    expires_at: float
    purpose: str = "auth"
    metadata: dict[str, Any] = field(default_factory=dict)

class VerifyRequest(BaseModel):
    token: str

class VerifyResponse(BaseModel):
    valid: bool
    did: str = ""
    issued_at: float = 0
    expires_at: float = 0
    error: str = ""

class RegisterRequest(BaseModel):
    did: str
    identity_card: str
    display_name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

class AgentStatus(BaseModel):
    did: str
    status: str  # "pending", "approved", "denied"
    display_name: str = ""
    registered_at: str = ""
    approved_at: str = ""
    identity_card: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

class ApproveRequest(BaseModel):
    admin_token: str = ""

# ---------------------------------------------------------------------------
# Auth Server
# ---------------------------------------------------------------------------

class AuthServer:
    """FastAPI-based HTTP server for hermes-id authentication.

    Usage::

        server = AuthServer(identity_dir="~/.hermes/identity")
        server.run(port=9488)

    Or mount the ``app`` directly::

        app.mount("/auth", server.app)
    """

    def __init__(
        self,
        identity_dir: Optional[str] = None,
        db_path: Optional[str] = None,
        token_ttl: int = _TOKEN_TTL,
        challenge_ttl: int = _CHALLENGE_TTL,
    ):
        self._storage = IdentityStorage(directory=identity_dir)
        self._token_ttl = token_ttl
        self._challenge_ttl = challenge_ttl

        # SQLite for agent registry
        self._db_path = Path(db_path or _AGENT_REGISTRY_DB)
        self._ensure_registry_db()

        # In-memory challenge store: did -> {"challenge": bytes, "expires": float}
        self._challenges: dict[str, dict[str, Any]] = {}

        # Build FastAPI app
        self.app = FastAPI(
            title="hermes-id Auth Server",
            version="1.0.0",
            description="Self-Sovereign Identity for agents — challenge-response auth, token issuance, and agent registry.",
        )
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        self._register_routes()

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

    def _ensure_registry_db(self) -> None:
        """Create the agent registry SQLite database if it doesn't exist."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                did TEXT PRIMARY KEY,
                identity_card TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                display_name TEXT DEFAULT '',
                registered_at TEXT NOT NULL,
                approved_at TEXT,
                metadata TEXT DEFAULT '{}'
            )
        """)
        conn.commit()
        conn.close()

    def _db_connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path))

    # ------------------------------------------------------------------
    # Token operations
    # ------------------------------------------------------------------

    def _get_keypair(self) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, IdentityCard]:
        """Load the server's identity keypair and card."""
        if not self._storage.exists():
            raise RuntimeError(
                "No identity configured. Run `hermes-id init` first."
            )
        password = os.environ.get("HERMES_ID_PASSPHRASE") or ""
        if not password:
            raise RuntimeError(
                "HERMES_ID_PASSPHRASE not set. Set it in the environment."
            )
        private_key = self._storage.unlock(password)
        public_key = private_key.public_key()
        card = self._storage.get_identity_card()
        return private_key, public_key, card

    def _sign_token(self, payload: dict[str, Any]) -> str:
        """Create an Ed25519-signed auth token.

        Format: base64url(payload) || "." || base64url(signature)
        """
        private_key, _, _ = self._get_keypair()
        payload_json = json.dumps(payload, separators=(",", ":"))
        payload_bytes = payload_json.encode("utf-8")
        signature = sign(private_key, payload_bytes)
        token = _b64(payload_bytes) + "." + _b64(signature)
        return token

    def verify_token(self, token: str) -> Optional[dict[str, Any]]:
        """Verify an Ed25519-signed auth token.

        Returns the payload dict if valid, None otherwise.
        """
        try:
            _, _, card = self._get_keypair()
            # Parse: payload_b64.signature_b64
            parts = token.split(".")
            if len(parts) != 2:
                return None
            payload_b64, sig_b64 = parts
            payload_bytes = _unb64(payload_b64)
            signature_bytes = _unb64(sig_b64)

            # Get public key from the identity card
            pub_b64 = card.public_key_multibase
            if not pub_b64:
                return None
            pub_raw = _unb64(pub_b64[1:])  # strip multibase prefix 'u'
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)

            # Verify
            try:
                public_key.verify(signature_bytes, payload_bytes)
            except InvalidSignature:
                return None

            payload = json.loads(payload_bytes.decode("utf-8"))

            # Check expiration
            if payload.get("expires_at", 0) < time.time():
                return None

            return payload
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    def _register_routes(self) -> None:
        app = self.app

        @app.get("/identity")
        def get_identity():
            """Return the server's identity card."""
            card = self._storage.get_identity_card()
            return json.loads(card.to_json())

        @app.post("/challenge")
        def create_challenge(req: ChallengeRequest):
            """Generate a random challenge for a DID."""
            if not req.did.startswith("did:"):
                raise HTTPException(400, "Invalid DID format")

            challenge = generate_challenge()
            challenge_b64 = _b64(challenge)
            expires_at = time.time() + self._challenge_ttl

            self._challenges[req.did] = {
                "challenge": challenge,
                "challenge_b64": challenge_b64,
                "expires_at": expires_at,
            }

            _, _, card = self._get_keypair()

            return ChallengeResponse(
                challenge_b64=challenge_b64,
                expires_at=expires_at,
                server_did=card.id,
            )

        @app.post("/authenticate")
        def authenticate(req: AuthenticateRequest):
            """Verify a signature and issue a signed auth token.

            Steps:
            1. Look up the challenge for this DID
            2. Verify the challenge hasn't expired
            3. Decode the provided identity card
            4. Verify the identity card's self-signature
            5. Check the agent is approved in the registry
            6. Verify the challenge signature using the card's public key
            7. Issue a signed auth token
            """
            # 1. Get challenge
            challenge_entry = self._challenges.pop(req.did, None)
            if not challenge_entry:
                raise HTTPException(400, "No challenge found. Call /challenge first.")

            # 2. Check expiration
            if challenge_entry["expires_at"] < time.time():
                raise HTTPException(401, "Challenge expired. Request a new one.")

            # 3. Decode identity card
            try:
                card_data = json.loads(req.identity_card)
                card = IdentityCard(**card_data)
            except (json.JSONDecodeError, TypeError) as e:
                raise HTTPException(400, f"Invalid identity card: {e}")

            # 4. Verify identity card self-signature
            if not verify_identity_card(card):
                raise HTTPException(401, "Identity card self-signature is invalid")

            # 5. Check agent is approved in registry
            conn = self._db_connect()
            row = conn.execute(
                "SELECT status FROM agents WHERE did = ?", (req.did,)
            ).fetchone()
            conn.close()

            if not row:
                raise HTTPException(
                    403,
                    "Agent not registered. First call POST /agents/register.",
                )
            if row[0] != "approved":
                raise HTTPException(
                    403,
                    f"Agent status is '{row[0]}'. Admin must approve first.",
                )

            # 6. Verify challenge signature
            challenge = challenge_entry["challenge"]
            try:
                sig_bytes = _unb64(req.signature_b64)
            except Exception as e:
                raise HTTPException(400, f"Invalid signature encoding: {e}")

            # Recover public key from identity card
            pub_b64 = card.public_key_multibase
            if not pub_b64:
                raise HTTPException(400, "Identity card has no public key")
            try:
                pub_raw = _unb64(pub_b64[1:])
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
            except Exception as e:
                raise HTTPException(400, f"Cannot parse public key: {e}")

            if not verify(public_key, challenge, sig_bytes):
                raise HTTPException(401, "Challenge signature invalid")

            # 7. Issue token
            now = time.time()
            payload = AuthTokenData(
                did=req.did,
                issuer=self._storage.get_identity_card().id,
                issued_at=now,
                expires_at=now + self._token_ttl,
                purpose="auth",
            )
            token = self._sign_token(payload.model_dump())
            return {"token": token, "expires_at": payload.expires_at, "did": req.did}

        @app.post("/verify")
        def verify_endpoint(req: VerifyRequest):
            """Verify a signed auth token."""
            payload = self.verify_token(req.token)
            if payload is None:
                return VerifyResponse(valid=False, error="Token invalid or expired")
            return VerifyResponse(
                valid=True,
                did=payload.get("did", ""),
                issued_at=payload.get("issued_at", 0),
                expires_at=payload.get("expires_at", 0),
            )

        # ------------------------------------------------------------------
        # Agent Registry endpoints
        # ------------------------------------------------------------------

        @app.get("/agents")
        def list_agents(
            status: Optional[str] = Query(None, pattern="^(pending|approved|denied)$"),
        ):
            """List all registered agents. Optionally filter by status."""
            conn = self._db_connect()
            if status:
                rows = conn.execute(
                    "SELECT did, status, display_name, registered_at, approved_at, identity_card, metadata FROM agents WHERE status = ?",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT did, status, display_name, registered_at, approved_at, identity_card, metadata FROM agents"
                ).fetchall()
            conn.close()

            agents = []
            for row in rows:
                agents.append({
                    "did": row[0],
                    "status": row[1],
                    "display_name": row[2],
                    "registered_at": row[3],
                    "approved_at": row[4],
                    "has_identity_card": bool(row[5]),
                    "metadata": json.loads(row[6]) if row[6] else {},
                })
            return {"agents": agents, "count": len(agents)}

        @app.post("/agents/register")
        def register_agent(req: RegisterRequest):
            """Self-register an agent with its identity card.

            The agent presents its DID and identity card. The server stores
            it in the registry with status='pending' until an admin approves.
            """
            # Validate DID matches identity card
            try:
                card_data = json.loads(req.identity_card)
                card = IdentityCard(**card_data)
            except (json.JSONDecodeError, TypeError) as e:
                raise HTTPException(400, f"Invalid identity card: {e}")

            if card.id != req.did:
                raise HTTPException(400, "DID in request doesn't match identity card")

            # Verify self-signature
            if not verify_identity_card(card):
                raise HTTPException(400, "Identity card self-signature is invalid")

            conn = self._db_connect()

            # Check if already registered
            existing = conn.execute(
                "SELECT status FROM agents WHERE did = ?", (req.did,)
            ).fetchone()
            if existing:
                conn.close()
                raise HTTPException(
                    409,
                    f"Agent already registered with status '{existing[0]}'",
                )

            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """INSERT INTO agents (did, identity_card, status, display_name, registered_at, metadata)
                   VALUES (?, ?, 'pending', ?, ?, ?)""",
                (req.did, req.identity_card, req.display_name, now, json.dumps(req.metadata)),
            )
            conn.commit()
            conn.close()

            return {
                "did": req.did,
                "status": "pending",
                "message": "Agent registered. Awaiting admin approval.",
            }

        @app.post("/agents/{did}/approve")
        def approve_agent(did: str):
            """Approve a pending agent. Can only approve agents with status='pending'."""
            conn = self._db_connect()
            existing = conn.execute(
                "SELECT status FROM agents WHERE did = ?", (did,)
            ).fetchone()
            if not existing:
                conn.close()
                raise HTTPException(404, "Agent not found")

            if existing[0] != "pending":
                conn.close()
                raise HTTPException(
                    409, f"Agent is already '{existing[0]}' (can only approve 'pending' agents)"
                )

            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "UPDATE agents SET status = 'approved', approved_at = ? WHERE did = ?",
                (now, did),
            )
            conn.commit()
            conn.close()

            return {"did": did, "status": "approved", "approved_at": now}

        @app.post("/agents/{did}/deny")
        def deny_agent(did: str):
            """Deny a pending agent."""
            conn = self._db_connect()
            existing = conn.execute(
                "SELECT status FROM agents WHERE did = ?", (did,)
            ).fetchone()
            if not existing:
                conn.close()
                raise HTTPException(404, "Agent not found")

            if existing[0] != "pending":
                conn.close()
                raise HTTPException(
                    409, f"Agent is already '{existing[0]}' (can only deny 'pending' agents)"
                )

            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "UPDATE agents SET status = 'denied' WHERE did = ?",
                (did,),
            )
            conn.commit()
            conn.close()

            return {"did": did, "status": "denied"}

        @app.get("/agents/{did}/status")
        def get_agent_status(did: str):
            """Check an agent's registration and approval status."""
            conn = self._db_connect()
            row = conn.execute(
                "SELECT did, status, display_name, registered_at, approved_at, metadata FROM agents WHERE did = ?",
                (did,),
            ).fetchone()
            conn.close()

            if not row:
                raise HTTPException(404, "Agent not found")

            return {
                "did": row[0],
                "status": row[1],
                "display_name": row[2],
                "registered_at": row[3],
                "approved_at": row[4],
                "metadata": json.loads(row[5]) if row[5] else {},
            }

        @app.delete("/agents/{did}")
        def delete_agent(did: str):
            """Remove an agent from the registry."""
            conn = self._db_connect()
            existing = conn.execute(
                "SELECT did FROM agents WHERE did = ?", (did,)
            ).fetchone()
            if not existing:
                conn.close()
                raise HTTPException(404, "Agent not found")

            conn.execute("DELETE FROM agents WHERE did = ?", (did,))
            conn.commit()
            conn.close()

            return {"did": did, "status": "deleted"}

        @app.get("/health")
        def health():
            return {"status": "ok", "did": self._storage.get_identity_card().id}

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(
        self,
        host: str = _DEFAULT_HOST,
        port: int = _DEFAULT_PORT,
        log_level: str = "info",
    ) -> None:
        """Start the auth server (blocking)."""
        import uvicorn
        print(f"🔐 hermes-id Auth Server starting on {host}:{port}")
        print(f"   Server DID: {self._storage.get_identity_card().id}")
        print(f"   Agent registry: {self._db_path}")
        print(f"   Token TTL: {self._token_ttl}s")
        uvicorn.run(self.app, host=host, port=port, log_level=log_level)


def run_server(
    identity_dir: Optional[str] = None,
    db_path: Optional[str] = None,
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
) -> None:
    """Convenience function to start the auth server."""
    server = AuthServer(identity_dir=identity_dir, db_path=db_path)
    server.run(host=host, port=port)


def verify_auth_token(token: str, identity_card_path: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Standalone token verification — useful for apps that load the server's identity card.

    Args:
        token: The signed auth token string.
        identity_card_path: Path to the server's identity card JSON file.
            If None, uses the default identity directory.

    Returns:
        The token payload dict if valid, None otherwise.
    """
    if identity_card_path:
        raw = Path(identity_card_path).read_text()
        card = IdentityCard.from_json(raw)
    else:
        storage = IdentityStorage()
        card = storage.get_identity_card()

    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig_b64 = parts
        payload_bytes = _unb64(payload_b64)
        signature_bytes = _unb64(sig_b64)

        pub_b64 = card.public_key_multibase
        if not pub_b64:
            return None
        pub_raw = _unb64(pub_b64[1:])
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)

        public_key.verify(signature_bytes, payload_bytes)
        payload = json.loads(payload_bytes.decode("utf-8"))

        if payload.get("expires_at", 0) < time.time():
            return None

        return payload
    except Exception:
        return None
