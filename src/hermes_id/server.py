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
    POST /token/refresh     → Refresh an expiring token

  Agent Registry (admin)
    GET    /agents                     → List agents (supports ?status=, ?page=, ?search=)
    POST   /agents/register            → Self-register with identity card
    POST   /agents/{did}/approve       → Admin approves agent
    POST   /agents/{did}/deny          → Admin denies agent
    GET    /agents/{did}/status        → Check agent approval status
    DELETE /agents/{did}               → Remove agent (requires admin key)

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

Admin Authentication
--------------------
  Admin endpoints (approve, deny, delete) require the ``X-Admin-Key`` header.
  Set ``HERMES_ID_ADMIN_KEY`` in the environment. If unset, a random key is
  generated and printed at startup.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import sqlite3
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, HTTPException, Header, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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
# Logging
# ---------------------------------------------------------------------------

_logger = logging.getLogger("hermes-id.server")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_PORT = 9488      # one up from the handshake port (9487)
_DEFAULT_HOST = "0.0.0.0"
_TOKEN_TTL = 3600 * 24    # 24 hours default token lifetime
_REFRESH_TOKEN_TTL = 3600 * 24 * 7  # 7 days for refresh tokens
_CHALLENGE_TTL = 300       # 5 minutes for challenge nonces
_PAGE_SIZE = 50           # default page size for agent list

_AGENT_REGISTRY_DB = "agent_registry.db"
_INVALIDATED_TOKENS_DB = "invalidated_tokens.db"

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

class TokenRefreshRequest(BaseModel):
    token: str

class AuthTokenData(BaseModel):
    did: str
    issuer: str
    issued_at: float
    expires_at: float
    token_id: str = ""  # unique token ID for blacklisting
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
    updated_at: str = ""
    approved_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

class RevokeRequest(BaseModel):
    token: str

# ---------------------------------------------------------------------------
# Rate limiter (in-memory, simple token bucket)
# ---------------------------------------------------------------------------

class RateLimiter:
    """Simple sliding-window rate limiter per IP."""

    def __init__(self, max_requests: int = 30, window_seconds: float = 60.0):
        self._max = max_requests
        self._window = window_seconds
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def check(self, client_ip: str) -> bool:
        now = time.time()
        cutoff = now - self._window
        bucket = self._buckets[client_ip]
        # Prune old entries
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        bucket.append(now)
        return len(bucket) <= self._max

    def reset(self, client_ip: str) -> None:
        self._buckets.pop(client_ip, None)


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
        admin_key: Optional[str] = None,
        cors_origins: Optional[list[str]] = None,
        rate_limit_max: int = 30,
        rate_limit_window: float = 60.0,
    ):
        self._storage = IdentityStorage(directory=identity_dir)
        self._token_ttl = token_ttl
        self._challenge_ttl = challenge_ttl

        # Cached keypair (loaded on first use, avoids decrypting on every request)
        self._cached_private_key: Optional[ed25519.Ed25519PrivateKey] = None
        self._cached_public_key: Optional[ed25519.Ed25519PublicKey] = None
        self._cached_card: Optional[IdentityCard] = None

        # Admin key
        self._admin_key = admin_key or os.environ.get("HERMES_ID_ADMIN_KEY", "")
        if not self._admin_key:
            self._admin_key = secrets.token_urlsafe(32)
            _logger.warning(
                "No admin key set via HERMES_ID_ADMIN_KEY or constructor. "
                "Generated random key: %s", self._admin_key[:16] + "..."
            )

        # SQLite databases
        self._db_path = Path(db_path or _AGENT_REGISTRY_DB)
        self._invalidation_db_path = self._db_path.parent / _INVALIDATED_TOKENS_DB
        self._ensure_registry_db()
        self._ensure_invalidation_db()

        # In-memory stores
        self._challenges: dict[str, dict[str, Any]] = {}
        self._rate_limiter = RateLimiter(max_requests=rate_limit_max, window_seconds=rate_limit_window)

        # Logging
        self._log = _logger

        # Build FastAPI app
        self.app = FastAPI(
            title="hermes-id Auth Server",
            version="1.1.0",
            description=(
                "Self-Sovereign Identity for agents — challenge-response auth, "
                "token issuance, agent registry with approval workflow.\n\n"
                "## Quick Start\n\n"
                "1. An agent calls `POST /challenge` to get a random nonce\n"
                "2. The agent signs the nonce with their Ed25519 key\n"
                "3. The agent calls `POST /authenticate` to prove identity\n"
                "4. The server issues a signed auth token\n"
                "5. Services call `POST /verify` to check the token"
            ),
            docs_url="/docs",
            redoc_url="/redoc",
            contact={
                "name": "Hermes ID",
                "url": "https://github.com/omiinaya/hermes-id",
            },
        )

        # CORS
        origins = cors_origins or os.environ.get(
            "HERMES_ID_CORS_ORIGINS", "*"
        ).split(",")
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=["X-Request-Id"],
        )

        # Exception handler for consistent error responses
        @self.app.exception_handler(HTTPException)
        async def http_exception_handler(request: Request, exc: HTTPException):
            return JSONResponse(
                status_code=exc.status_code,
                content={"error": exc.detail, "code": exc.status_code},
            )

        self._register_routes()
        self._log.info("AuthServer initialized (DID will be logged on first request)")

    # ------------------------------------------------------------------
    # Rate limiting dependency
    # ------------------------------------------------------------------

    def _check_rate_limit(self, request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        if not self._rate_limiter.check(client_ip):
            raise HTTPException(429, "Too many requests. Try again later.")

    # ------------------------------------------------------------------
    # Admin auth dependency
    # ------------------------------------------------------------------

    def _require_admin(self, x_admin_key: str = Header("")) -> None:
        if not x_admin_key or x_admin_key != self._admin_key:
            raise HTTPException(
                403, "Invalid or missing admin key. Provide X-Admin-Key header."
            )

    # ------------------------------------------------------------------
    # Databases
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
                updated_at TEXT NOT NULL,
                approved_at TEXT,
                metadata TEXT DEFAULT '{}'
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)
        """)
        conn.commit()
        conn.close()

    def _ensure_invalidation_db(self) -> None:
        """Create the token invalidation database."""
        self._invalidation_db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._invalidation_db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS invalidated_tokens (
                token_id TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                invalidated_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_invalidated_did
            ON invalidated_tokens(did)
        """)
        conn.commit()
        conn.close()

    def _db_connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path))

    def _invalidation_db_connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._invalidation_db_path))

    # ------------------------------------------------------------------
    # Token operations
    # ------------------------------------------------------------------

    def _get_keypair(self) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, IdentityCard]:
        """Load the server's identity keypair and card (cached after first load)."""
        if self._cached_private_key is not None:
            return self._cached_private_key, self._cached_public_key, self._cached_card

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

        # Cache
        self._cached_private_key = private_key
        self._cached_public_key = public_key
        self._cached_card = card

        self._log.info("Keypair loaded and cached (DID=%s)", card.id)
        return private_key, public_key, card

    def _sign_token(self, payload: dict[str, Any]) -> str:
        """Create an Ed25519-signed auth token.

        Format: base64url(payload) || "." || base64url(signature)
        """
        private_key, _, _ = self._get_keypair()
        payload_json = json.dumps(payload, separators=(",", ":"))
        payload_bytes = payload_json.encode("utf-8")
        signature = sign(private_key, payload_bytes)
        return _b64(payload_bytes) + "." + _b64(signature)

    def _parse_token(self, token: str) -> Optional[dict[str, Any]]:
        """Parse and verify the token signature and expiration.

        Returns the payload dict if valid, None otherwise.
        Does NOT check blacklist — call :meth:`_is_token_invalidated` separately.
        """
        try:
            parts = token.split(".")
            if len(parts) != 2:
                return None
            payload_b64, sig_b64 = parts
            payload_bytes = _unb64(payload_b64)
            signature_bytes = _unb64(sig_b64)

            # Get the server's public key from the identity card
            _, _, card = self._get_keypair()
            pub_b64 = card.public_key_multibase
            if not pub_b64:
                return None
            pub_raw = _unb64(pub_b64[1:])  # strip multibase prefix 'u'
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)

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

    def verify_token(self, token: str) -> Optional[dict[str, Any]]:
        """Verify a token, including checking the invalidation list.

        Returns the payload dict if valid, None otherwise.
        """
        payload = self._parse_token(token)
        if payload is None:
            return None

        # Check blacklist
        token_id = payload.get("token_id", "")
        if token_id and self._is_token_invalidated(token_id):
            return None

        return payload

    def _is_token_invalidated(self, token_id: str) -> bool:
        """Check if a token_id has been invalidated."""
        conn = self._invalidation_db_connect()
        try:
            row = conn.execute(
                "SELECT token_id FROM invalidated_tokens WHERE token_id = ?",
                (token_id,),
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    def _invalidate_token(self, token_id: str, did: str) -> None:
        """Add a token to the invalidation list."""
        conn = self._invalidation_db_connect()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO invalidated_tokens (token_id, did, invalidated_at) VALUES (?, ?, ?)",
                (token_id, did, time.time()),
            )
            conn.commit()
        finally:
            conn.close()

    def _generate_token_id(self) -> str:
        return secrets.token_urlsafe(16)

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    def _register_routes(self) -> None:
        app = self.app
        rate_limit = self._check_rate_limit
        require_admin = self._require_admin

        # ------------------------------------------------------------------
        # Identity
        # ------------------------------------------------------------------

        @app.get("/identity")
        def get_identity():
            """Return the server's identity card."""
            card = self._storage.get_identity_card()
            if not card:
                raise HTTPException(500, "Server identity not configured")
            return json.loads(card.to_json())

        @app.get("/health")
        def health():
            """Health check — returns server DID and status."""
            card = self._storage.get_identity_card()
            return {
                "status": "ok",
                "did": card.id if card else "unconfigured",
                "version": "1.1.0",
                "uptime": time.time(),
            }

        # ------------------------------------------------------------------
        # Authentication
        # ------------------------------------------------------------------

        @app.post("/challenge")
        def create_challenge(req: ChallengeRequest, request: Request):
            """Generate a random challenge for a DID. Rate-limited."""
            rate_limit(request)

            if not req.did.startswith("did:"):
                raise HTTPException(400, "Invalid DID format — must start with 'did:'")

            challenge = generate_challenge()
            challenge_b64 = _b64(challenge)
            expires_at = time.time() + self._challenge_ttl

            self._challenges[req.did] = {
                "challenge": challenge,
                "challenge_b64": challenge_b64,
                "expires_at": expires_at,
            }

            _, _, card = self._get_keypair()

            self._log.info("Challenge issued for DID=%s", req.did)

            return ChallengeResponse(
                challenge_b64=challenge_b64,
                expires_at=expires_at,
                server_did=card.id,
            )

        @app.post("/authenticate")
        def authenticate(req: AuthenticateRequest, request: Request):
            """Verify a signature and issue a signed auth token. Rate-limited."""
            rate_limit(request)

            # 1. Get challenge (one-time use)
            challenge_entry = self._challenges.pop(req.did, None)
            if not challenge_entry:
                raise HTTPException(400, "No challenge found. Call POST /challenge first.")

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

            # 5. Check DID matches
            if card.id != req.did:
                raise HTTPException(400, "DID in identity card doesn't match request DID")

            # 6. Check agent is approved in registry
            conn = self._db_connect()
            try:
                row = conn.execute(
                    "SELECT status FROM agents WHERE did = ?", (req.did,)
                ).fetchone()
            finally:
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

            # 7. Verify challenge signature
            challenge = challenge_entry["challenge"]
            try:
                sig_bytes = _unb64(req.signature_b64)
            except Exception as e:
                raise HTTPException(400, f"Invalid signature encoding: {e}")

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

            # 8. Issue token
            now = time.time()
            token_id = self._generate_token_id()
            payload = AuthTokenData(
                did=req.did,
                issuer=self._storage.get_identity_card().id,
                issued_at=now,
                expires_at=now + self._token_ttl,
                token_id=token_id,
                purpose="auth",
            )
            token_str = self._sign_token(payload.model_dump())

            self._log.info(
                "Token issued for DID=%s token_id=%s expires_at=%s",
                req.did, token_id, payload.expires_at,
            )

            return {
                "token": token_str,
                "token_id": token_id,
                "expires_at": payload.expires_at,
                "did": req.did,
            }

        @app.post("/verify")
        def verify_endpoint(req: VerifyRequest):
            """Verify a signed auth token."""
            payload = self.verify_token(req.token)
            if payload is None:
                return VerifyResponse(
                    valid=False,
                    error="Token invalid, expired, or revoked",
                )
            return VerifyResponse(
                valid=True,
                did=payload.get("did", ""),
                issued_at=payload.get("issued_at", 0),
                expires_at=payload.get("expires_at", 0),
            )

        @app.post("/token/refresh")
        def refresh_token(req: TokenRefreshRequest):
            """Refresh an expiring token. Issues a new token with a fresh TTL.

            The old token must still be valid. The new token extends by the
            configured ``token_ttl`` (default 24h) from the current time.
            """
            payload = self.verify_token(req.token)
            if payload is None:
                raise HTTPException(401, "Token invalid, expired, or revoked")

            # Cannot refresh beyond the max refresh window
            issued_at = payload.get("issued_at", 0)
            if time.time() - issued_at > _REFRESH_TOKEN_TTL:
                raise HTTPException(
                    401, "Token too old to refresh. Please re-authenticate."
                )

            now = time.time()
            new_token_id = self._generate_token_id()
            new_payload = AuthTokenData(
                did=payload["did"],
                issuer=payload["issuer"],
                issued_at=now,
                expires_at=now + self._token_ttl,
                token_id=new_token_id,
                purpose="auth",
            )
            new_token = self._sign_token(new_payload.model_dump())

            self._log.info("Token refreshed for DID=%s new_token_id=%s", payload["did"], new_token_id)

            return {
                "token": new_token,
                "token_id": new_token_id,
                "expires_at": new_payload.expires_at,
                "did": payload["did"],
            }

        @app.post("/token/revoke")
        def revoke_token(req: RevokeRequest):
            """Revoke a token before it expires."""
            payload = self._parse_token(req.token)
            if payload is None:
                # Token is already invalid for some reason — still return success
                # to avoid leaking whether a token_id was valid
                return {"status": "revoked"}

            token_id = payload.get("token_id", "")
            if token_id:
                self._invalidate_token(token_id, payload.get("did", ""))
                self._log.info("Token revoked: token_id=%s did=%s", token_id, payload.get("did"))

            return {"status": "revoked"}

        # ------------------------------------------------------------------
        # Agent Registry
        # ------------------------------------------------------------------

        @app.get("/agents")
        def list_agents(
            status: Optional[str] = Query(None, pattern="^(pending|approved|denied)$"),
            page: int = Query(1, ge=1, description="Page number (1-indexed)"),
            page_size: int = Query(_PAGE_SIZE, ge=1, le=200, alias="page_size"),
            search: Optional[str] = Query(None, min_length=1, max_length=100),
            x_admin_key: str = Header(""),
        ):
            """List all registered agents. Requires admin key."""
            require_admin(x_admin_key)

            conn = self._db_connect()
            try:
                conditions: list[str] = []
                params: list[Any] = []

                if status:
                    conditions.append("status = ?")
                    params.append(status)

                if search:
                    conditions.append("(did LIKE ? OR display_name LIKE ?)")
                    params.extend([f"%{search}%", f"%{search}%"])

                where_clause = ""
                if conditions:
                    where_clause = "WHERE " + " AND ".join(conditions)

                # Count total
                count_row = conn.execute(
                    f"SELECT COUNT(*) FROM agents {where_clause}", params
                ).fetchone()
                total = count_row[0] if count_row else 0

                # Fetch page
                offset = (page - 1) * page_size
                rows = conn.execute(
                    f"SELECT did, status, display_name, registered_at, updated_at, approved_at, metadata FROM agents {where_clause} ORDER BY registered_at DESC LIMIT ? OFFSET ?",
                    params + [page_size, offset],
                ).fetchall()

                agents = []
                for row in rows:
                    agents.append({
                        "did": row[0],
                        "status": row[1],
                        "display_name": row[2],
                        "registered_at": row[3],
                        "updated_at": row[4],
                        "approved_at": row[5],
                        "metadata": json.loads(row[6]) if row[6] else {},
                    })
            finally:
                conn.close()

            return {
                "agents": agents,
                "total": total,
                "page": page,
                "page_size": page_size,
                "pages": (total + page_size - 1) // page_size if total > 0 else 0,
            }

        @app.post("/agents/register")
        def register_agent(req: RegisterRequest, request: Request):
            """Self-register an agent with its identity card. Rate-limited."""
            rate_limit(request)

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
            try:
                # Check if already registered
                existing = conn.execute(
                    "SELECT status FROM agents WHERE did = ?", (req.did,)
                ).fetchone()
                if existing:
                    raise HTTPException(
                        409,
                        f"Agent already registered with status '{existing[0]}'",
                    )

                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    """INSERT INTO agents (did, identity_card, status, display_name, registered_at, updated_at, metadata)
                       VALUES (?, ?, 'pending', ?, ?, ?, ?)""",
                    (req.did, req.identity_card, req.display_name, now, now, json.dumps(req.metadata)),
                )
                conn.commit()
            finally:
                conn.close()

            self._log.info("Agent registered: DID=%s display_name='%s'", req.did, req.display_name)

            return {
                "did": req.did,
                "status": "pending",
                "message": "Agent registered. Awaiting admin approval.",
            }

        @app.post("/agents/{did}/approve")
        def approve_agent(did: str, x_admin_key: str = Header("")):
            """Approve a pending agent. Requires admin key."""
            require_admin(x_admin_key)

            conn = self._db_connect()
            try:
                existing = conn.execute(
                    "SELECT status FROM agents WHERE did = ?", (did,)
                ).fetchone()
                if not existing:
                    raise HTTPException(404, "Agent not found")

                if existing[0] != "pending":
                    raise HTTPException(
                        409,
                        f"Agent is already '{existing[0]}' (can only approve 'pending' agents)",
                    )

                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "UPDATE agents SET status = 'approved', approved_at = ?, updated_at = ? WHERE did = ?",
                    (now, now, did),
                )
                conn.commit()
            finally:
                conn.close()

            self._log.info("Agent approved: DID=%s", did)

            return {"did": did, "status": "approved"}

        @app.post("/agents/{did}/deny")
        def deny_agent(did: str, x_admin_key: str = Header("")):
            """Deny a pending agent. Requires admin key."""
            require_admin(x_admin_key)

            conn = self._db_connect()
            try:
                existing = conn.execute(
                    "SELECT status FROM agents WHERE did = ?", (did,)
                ).fetchone()
                if not existing:
                    raise HTTPException(404, "Agent not found")

                if existing[0] != "pending":
                    raise HTTPException(
                        409,
                        f"Agent is already '{existing[0]}' (can only deny 'pending' agents)",
                    )

                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "UPDATE agents SET status = 'denied', updated_at = ? WHERE did = ?",
                    (now, did),
                )
                conn.commit()
            finally:
                conn.close()

            self._log.info("Agent denied: DID=%s", did)

            return {"did": did, "status": "denied"}

        @app.get("/agents/{did}/status")
        def get_agent_status(did: str, x_admin_key: str = Header("")):
            """Check an agent's registration and approval status. Requires admin key."""
            require_admin(x_admin_key)
            return _agent_status_internal(did)

        def _agent_status_internal(did: str) -> dict:
            """Internal helper for agent status lookup."""
            conn = self._db_connect()
            try:
                row = conn.execute(
                    "SELECT did, status, display_name, registered_at, updated_at, approved_at, metadata FROM agents WHERE did = ?",
                    (did,),
                ).fetchone()
            finally:
                conn.close()

            if not row:
                raise HTTPException(404, "Agent not found")

            return {
                "did": row[0],
                "status": row[1],
                "display_name": row[2],
                "registered_at": row[3],
                "updated_at": row[4],
                "approved_at": row[5],
                "metadata": json.loads(row[6]) if row[6] else {},
            }

        @app.delete("/agents/{did}")
        def delete_agent(did: str, x_admin_key: str = Header("")):
            """Remove an agent from the registry. Requires admin key."""
            require_admin(x_admin_key)

            conn = self._db_connect()
            try:
                existing = conn.execute(
                    "SELECT did FROM agents WHERE did = ?", (did,)
                ).fetchone()
                if not existing:
                    raise HTTPException(404, "Agent not found")

                conn.execute("DELETE FROM agents WHERE did = ?", (did,))
                conn.commit()
            finally:
                conn.close()

            self._log.info("Agent deleted: DID=%s", did)

            return {"did": did, "status": "deleted"}

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(
        self,
        host: str = _DEFAULT_HOST,
        port: int = _DEFAULT_PORT,
        log_level: str = "info",
        ssl_certfile: Optional[str] = None,
        ssl_keyfile: Optional[str] = None,
    ) -> None:
        """Start the auth server (blocking).

        Args:
            host: Bind address.
            port: TCP port.
            log_level: Uvicorn log level.
            ssl_certfile: Path to TLS certificate (PEM) to serve HTTPS.
            ssl_keyfile: Path to TLS private key (PEM) for the certificate.
        """
        import uvicorn

        card = self._storage.get_identity_card()
        scheme = "https" if ssl_certfile else "http"
        print(f"🔐  hermes-id Auth Server v1.2.0")
        print(f"    Server DID:    {card.id}")
        print(f"    Listening:     {scheme}://{host}:{port}")
        print(f"    API docs:      {scheme}://{host}:{port}/docs")
        print(f"    TLS:           {'✅ enabled' if ssl_certfile else '❌ disabled (use --tls-cert/--tls-key for HTTPS)'}")
        print(f"    Agent registry: {self._db_path}")
        print(f"    Token TTL:     {self._token_ttl}s")
        print(f"    Admin key:     {self._admin_key[:16]}... (set HERMES_ID_ADMIN_KEY to customize)")
        print()

        uvicorn.run(
            self.app,
            host=host,
            port=port,
            log_level=log_level,
            access_log=True,
            ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile,
        )


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def run_server(
    identity_dir: Optional[str] = None,
    db_path: Optional[str] = None,
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    admin_key: Optional[str] = None,
    cors_origins: Optional[list[str]] = None,
    ssl_certfile: Optional[str] = None,
    ssl_keyfile: Optional[str] = None,
) -> None:
    """Convenience function to start the auth server."""
    server = AuthServer(
        identity_dir=identity_dir,
        db_path=db_path,
        admin_key=admin_key,
        cors_origins=cors_origins,
    )
    server.run(host=host, port=port, ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)


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
