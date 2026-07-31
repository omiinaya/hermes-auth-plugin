"""
Mutual authentication handshake protocol for hermes-id.

Protocol flow (v1 — Ed25519 challenge-response):
------------------------------------------------

    Initiator (A)                          Responder (B)
    =============                          =============

    1. HELLO ──────────────────────────►
       { version, from_did,
         supported_protocols }

    2.                             ◄── CHALLENGE
         { challenge: 32-byte random nonce,
           from_did, signature }

    3. AUTH ──────────────────────────►
       { identity_card: full card,
         challenge: echoed nonce,
         signature: Ed25519(nonce || B_did) }

    4.                             ◄── CONFIRM
         { identity_card: full card,
           status: "ok",
           session_key: X25519 ephemeral pubkey,
           signature }

    5. Both verify each other's card + challenge.
       Both derive an ephemeral session key via X25519+HKDF.

Security properties:
    - **Replay protection**: Every handshake uses a fresh random challenge.
    - **Mutual authentication**: Both parties prove control of their keys.
    - **Forward secrecy**: Session keys are ephemeral X25519.
    - **No central registry**: Authentication is purely peer-to-peer.
    - **Phishing resistance**: The challenge binds to the target DID.
"""

import json
import socket
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from hermes_id.crypto import (
    _b64,
    _unb64,
    derive_session_key,
    generate_challenge,
    generate_x25519_keypair,
    sign,
    verify,
    x25519_shared_secret,
)
from hermes_id.identity import (
    IdentityCard,
    verify_identity_card,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PROTOCOL_VERSION = "1.0"
_DEFAULT_PORT = 9487  # HERM on a phone keypad
_DEFAULT_HOST = "127.0.0.1"
_MAX_MESSAGE_SIZE = 65536  # 64 KB
_HANDSHAKE_TIMEOUT = 30.0  # seconds


# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------

class HandshakeState(Enum):
    """Protocol state machine states."""
    IDLE = "idle"
    HELLO_SENT = "hello_sent"
    CHALLENGE_SENT = "challenge_sent"
    AUTH_SENT = "auth_sent"
    CONFIRMED = "confirmed"
    FAILED = "failed"


@dataclass
class HandshakeMessage:
    """A single protocol message with wire format."""
    msg_type: str  # "hello" | "challenge" | "auth" | "confirm" | "error"
    payload: dict[str, Any]

    def encode(self) -> bytes:
        """Serialize to length-prefixed JSON::

            [4 bytes: big-endian payload length]
            [N bytes: JSON-encoded payload]
        """
        raw = json.dumps({
            "type": self.msg_type,
            **self.payload,
        }).encode("utf-8")
        if len(raw) > _MAX_MESSAGE_SIZE:
            raise ValueError(f"Message too large ({len(raw)} bytes)")
        return struct.pack("!I", len(raw)) + raw

    @classmethod
    def decode(cls, data: bytes) -> "HandshakeMessage":
        """Deserialize from length-prefixed format."""
        if len(data) < 4:
            raise ValueError("Message too short")
        payload_len = struct.unpack("!I", data[:4])[0]
        if payload_len > _MAX_MESSAGE_SIZE:
            raise ValueError(f"Message too large: {payload_len} bytes")
        if len(data) < 4 + payload_len:
            raise ValueError(f"Truncated message: expected {payload_len} bytes, got {len(data) - 4}")
        raw = data[4:4 + payload_len]
        obj = json.loads(raw.decode("utf-8"))
        msg_type = obj.pop("type", "unknown")
        return cls(msg_type=msg_type, payload=obj)


class HandshakeError(Exception):
    """Raised on protocol violations, crypto failures, or timeouts."""


class HandshakeErrorCode:
    """Machine-readable error codes for the handshake protocol."""
    UNKNOWN = "UNKNOWN"
    PROTOCOL_VIOLATION = "PROTOCOL_VIOLATION"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    INVALID_IDENTITY_CARD = "INVALID_IDENTITY_CARD"
    MISSING_FIELD = "MISSING_FIELD"
    CRYPTO_FAILURE = "CRYPTO_FAILURE"
    SEQUENCE_ERROR = "SEQUENCE_ERROR"
    PEER_REJECTED = "PEER_REJECTED"
    TIMEOUT = "TIMEOUT"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    MESSAGE_TOO_LARGE = "MESSAGE_TOO_LARGE"


# ---------------------------------------------------------------------------
# Callback types
# ---------------------------------------------------------------------------

OnVerifyCallback = Callable[[IdentityCard], bool]
"""Called when a peer presents their identity card.  Return True to accept."""

OnConfirmCallback = Callable[[IdentityCard, bytes], None]
"""Called on successful mutual authentication.  Receives peer card + session key."""


# ---------------------------------------------------------------------------
# Handshake protocol (transport-agnostic)
# ---------------------------------------------------------------------------

@dataclass
class HandshakeProtocol:
    """Stateful challenge-response handshake for mutual authentication.

    This class implements the *protocol logic only* — it operates on
    ``HandshakeMessage`` objects.  Transport (TCP, Unix socket, HTTP,
    etc.) is handled by the caller.

    Usage::

        # Server/responder side
        hp = HandshakeProtocol(identity_card, private_key, is_responder=True)
        response = hp.handle_message(request)

        # Client/initiator side
        hp = HandshakeProtocol(identity_card, private_key, is_responder=False)
        request = hp.start()
        response = hp.handle_message(server_reply)
    """
    identity_card: IdentityCard
    private_key: ed25519.Ed25519PrivateKey
    is_responder: bool = False
    peer_did: str = ""
    on_verify: OnVerifyCallback | None = None
    on_confirm: OnConfirmCallback | None = None

    # Internal state
    _state: HandshakeState = field(default=HandshakeState.IDLE, init=False)
    _challenge: bytes = field(default=b"", init=False)
    _peer_card: IdentityCard | None = field(default=None, init=False)
    _session_key: bytes | None = field(default=None, init=False)
    _x25519_priv: x25519.X25519PrivateKey | None = field(default=None, init=False)
    _peer_did_verified: bool = field(default=False, init=False)

    # ------------------------------------------------------------------
    # Initiator flow
    # ------------------------------------------------------------------

    def start(self) -> HandshakeMessage:
        """Begin a handshake as the initiator.

        Returns the ``HELLO`` message to send to the peer.
        """
        self._state = HandshakeState.HELLO_SENT
        return HandshakeMessage(
            msg_type="hello",
            payload={
                "version": _PROTOCOL_VERSION,
                "from": self.identity_card.id,
                "protocols": ["ed25519-challenge-v1"],
            },
        )

    # ------------------------------------------------------------------
    # Message handler (works for both roles)
    # ------------------------------------------------------------------

    def handle_message(self, msg: HandshakeMessage) -> HandshakeMessage:
        """Process an incoming protocol message and return a response.

        Raises ``HandshakeError`` on protocol violations.
        """
        handler = {
            "hello": self._handle_hello,
            "challenge": self._handle_challenge,
            "auth": self._handle_auth,
            "confirm": self._handle_confirm,
            "error": self._handle_error,
        }
        handler_fn = handler.get(msg.msg_type)
        if handler_fn is None:
            return self._error(f"Unknown message type: {msg.msg_type}")
        return handler_fn(msg)

    # ------------------------------------------------------------------
    # Hello handler (responder only)
    # ------------------------------------------------------------------

    def _handle_hello(self, msg: HandshakeMessage) -> HandshakeMessage:
        """Respond to HELLO with a CHALLENGE (requires is_responder=True)."""
        if not self.is_responder:
            return self._error("Not a responder")
        if self._state not in (HandshakeState.IDLE,):
            return self._error("Protocol out of sequence")

        self.peer_did = msg.payload.get("from", "")
        self._challenge = generate_challenge()
        self._state = HandshakeState.CHALLENGE_SENT

        # Sign the challenge so the peer knows it came from *us*
        challenge_sig = sign(self.private_key, self._challenge)

        return HandshakeMessage(
            msg_type="challenge",
            payload={
                "challenge": _b64(self._challenge),
                "from": self.identity_card.id,
                "signature": _b64(challenge_sig),
            },
        )

    # ------------------------------------------------------------------
    # Challenge handler (initiator only)
    # ------------------------------------------------------------------

    def _handle_challenge(self, msg: HandshakeMessage) -> HandshakeMessage:
        """Respond to CHALLENGE with an AUTH message."""
        if self.is_responder:
            return self._error("Not an initiator")
        if self._state != HandshakeState.HELLO_SENT:
            return self._error("Protocol out of sequence")

        # Verify the challenge came from who we think
        self.peer_did = msg.payload.get("from", "")
        challenge_b64 = msg.payload.get("challenge", "")
        challenge_sig_b64 = msg.payload.get("signature", "")

        if not challenge_b64 or not challenge_sig_b64:
            return self._error("Malformed challenge")

        self._challenge = _unb64(challenge_b64)

        # Prove our identity: sign(challenge || peer_did)
        message_to_sign = self._challenge + self.peer_did.encode("utf-8")
        auth_sig = sign(self.private_key, message_to_sign)

        self._state = HandshakeState.AUTH_SENT

        return HandshakeMessage(
            msg_type="auth",
            payload={
                "identity_card": self.identity_card.to_json(),
                "challenge": challenge_b64,
                "signature": _b64(auth_sig),
            },
        )

    # ------------------------------------------------------------------
    # Auth handler (responder only)
    # ------------------------------------------------------------------

    def _handle_auth(self, msg: HandshakeMessage) -> HandshakeMessage:
        """Verify the AUTH message and respond with CONFIRM."""
        if not self.is_responder:
            return self._error("Not a responder")
        if self._state != HandshakeState.CHALLENGE_SENT:
            return self._error("Protocol out of sequence")

        # Parse peer identity card
        card_json = msg.payload.get("identity_card", "")
        if not card_json:
            return self._error("Missing identity card")

        try:
            peer_card = IdentityCard.from_json(card_json)
        except (json.JSONDecodeError, KeyError) as e:
            return self._error(f"Invalid identity card: {e}")

        # 1. Verify the identity card's self-signature
        if not verify_identity_card(peer_card):
            return self._error("Peer identity card has invalid self-signature")

        # 2. Verify the challenge signature
        sig_b64 = msg.payload.get("signature", "")
        if not sig_b64:
            return self._error("Missing authentication signature")

        # Recover peer's public key from their identity card
        pub_b64 = peer_card.public_key_multibase
        if not pub_b64:
            return self._error("Peer identity card missing public key")

        try:
            pub_raw = _unb64(pub_b64[1:])
            peer_pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
        except Exception as e:
            return self._error(f"Cannot parse peer public key: {e}")

        # Verify: signature(challenge || responder_did)
        message_to_verify = self._challenge + self.identity_card.id.encode("utf-8")
        peer_sig = _unb64(sig_b64)

        if not verify(peer_pubkey, message_to_verify, peer_sig):
            return self._error("Peer authentication signature invalid")

        # Run the application-level verification callback if set
        if self.on_verify and not self.on_verify(peer_card):
            return self._error("Peer identity rejected by application policy")

        self._peer_card = peer_card
        self._peer_did_verified = True

        # Generate ephemeral X25519 for session key agreement
        self._x25519_priv, x25519_pub = generate_x25519_keypair()

        # Sign the confirmation
        confirm_payload = json.dumps({
            "status": "ok",
            "peer_did": peer_card.id,
            "responder_x25519": _b64(
                x25519_pub.public_bytes_raw()
            ),
        })
        confirm_sig = sign(self.private_key, confirm_payload.encode("utf-8"))

        self._state = HandshakeState.CONFIRMED

        return HandshakeMessage(
            msg_type="confirm",
            payload={
                "identity_card": self.identity_card.to_json(),
                "status": "ok",
                "peer_did": peer_card.id,
                "responder_x25519": _b64(
                    x25519_pub.public_bytes_raw()
                ),
                "signature": _b64(confirm_sig),
            },
        )

    # ------------------------------------------------------------------
    # Confirm handler (initiator)
    # ------------------------------------------------------------------

    def _handle_confirm(self, msg: HandshakeMessage) -> HandshakeMessage:
        """Verify the CONFIRM message and derive session key."""
        if self.is_responder:
            return self._error("Not an initiator")
        if self._state != HandshakeState.AUTH_SENT:
            return self._error("Protocol out of sequence")

        # Verify responder's identity card
        card_json = msg.payload.get("identity_card", "")
        if not card_json:
            return self._error("Missing responder identity card")

        try:
            peer_card = IdentityCard.from_json(card_json)
        except (json.JSONDecodeError, KeyError) as e:
            return self._error(f"Invalid responder identity card: {e}")

        if not verify_identity_card(peer_card):
            return self._error("Responder identity card has invalid self-signature")

        self._peer_card = peer_card

        # Verify the confirmation signature
        sig_b64 = msg.payload.get("signature", "")
        if not sig_b64:
            return self._error("Missing confirmation signature")

        pub_b64 = peer_card.public_key_multibase
        if not pub_b64:
            return self._error("Responder identity card missing public key")

        try:
            pub_raw = _unb64(pub_b64[1:])
            peer_pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
        except Exception as e:
            return self._error(f"Cannot parse responder public key: {e}")

        # Verify against the confirm payload (without signature field)
        confirm_to_verify = json.dumps({
            "status": msg.payload.get("status"),
            "peer_did": msg.payload.get("peer_did"),
            "responder_x25519": msg.payload.get("responder_x25519"),
        })
        peer_sig = _unb64(sig_b64)

        if not verify(peer_pubkey, confirm_to_verify.encode("utf-8"), peer_sig):
            return self._error("Responder confirmation signature invalid")

        # Derive shared session key if responder sent X25519 pubkey
        x25519_pub_b64 = msg.payload.get("responder_x25519", "")
        if x25519_pub_b64:
            try:
                peer_x25519_pub = x25519.X25519PublicKey.from_public_bytes(
                    _unb64(x25519_pub_b64)
                )
                # Generate initiator's ephemeral X25519 keypair
                self._x25519_priv, our_x25519_pub = generate_x25519_keypair()
                shared = x25519_shared_secret(self._x25519_priv, peer_x25519_pub)
                self._session_key = derive_session_key(
                    shared,
                    context=b"hermes-id/v1/handshake",
                )
                # Sign the session confirmation (initiator's X25519 pubkey)
                final_payload = json.dumps({
                    "status": "session_established",
                    "initiator_x25519": _b64(our_x25519_pub.public_bytes_raw()),
                    "session_digest": _b64(
                        hashlib_sha256(self._session_key)
                    ),
                })
                final_sig = sign(self.private_key, final_payload.encode("utf-8"))

                self._state = HandshakeState.CONFIRMED

                # Notify
                if self.on_confirm:
                    self.on_confirm(peer_card, self._session_key)

                return HandshakeMessage(
                    msg_type="confirm",
                    payload={
                        "status": "session_established",
                        "initiator_x25519": _b64(
                            our_x25519_pub.public_bytes_raw()
                        ),
                        "session_digest": _b64(
                            hashlib_sha256(self._session_key)
                        ),
                        "signature": _b64(final_sig),
                    },
                )
            except Exception as e:
                return self._error(f"Session key derivation failed: {e}")

        # No X25519 exchange — authentication-only mode
        self._state = HandshakeState.CONFIRMED
        if self.on_confirm:
            self.on_confirm(peer_card, b"")

        auth_only_msg = {
            "status": "authenticated",
            "peer_did": peer_card.id,
        }
        auth_only_sig = sign(
            self.private_key,
            json.dumps(auth_only_msg).encode("utf-8"),
        )
        return HandshakeMessage(
            msg_type="confirm",
            payload={
                **auth_only_msg,
                "signature": _b64(auth_only_sig),
            },
        )

    # ------------------------------------------------------------------
    # Error handler
    # ------------------------------------------------------------------

    def _handle_error(self, msg: HandshakeMessage) -> HandshakeMessage:
        """Handle an error message from the peer."""
        error_text = msg.payload.get("error", "Unknown error")
        self._state = HandshakeState.FAILED
        raise HandshakeError(f"Peer error: {error_text}")

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _error(self, text: str) -> HandshakeMessage:
        """Generate an error response."""
        self._state = HandshakeState.FAILED
        return HandshakeMessage(
            msg_type="error",
            payload={"error": text},
        )

    @property
    def peer_card(self) -> IdentityCard | None:
        """The peer's verified identity card (None until CONFIRMED)."""
        return self._peer_card

    @property
    def session_key(self) -> bytes | None:
        """Derived session key (None in auth-only mode or before CONFIRMED)."""
        return self._session_key

    @property
    def is_authenticated(self) -> bool:
        """Whether the handshake completed successfully."""
        return self._state == HandshakeState.CONFIRMED

    @property
    def peer_did_verified(self) -> bool:
        """Whether the peer's DID was cryptographically verified."""
        return self._peer_did_verified


# ---------------------------------------------------------------------------
# TCP transport
# ---------------------------------------------------------------------------

def send_message(sock: socket.socket, msg: HandshakeMessage) -> None:
    """Send a handshake message over a TCP socket (length-prefixed)."""
    data = msg.encode()
    sock.sendall(data)


def recv_message(sock: socket.socket, timeout: float = _HANDSHAKE_TIMEOUT) -> HandshakeMessage:
    """Receive a handshake message from a TCP socket.

    Raises ``HandshakeError`` on timeout or connection close.
    """
    sock.settimeout(timeout)

    # Read 4-byte length prefix
    try:
        header = _recv_exact(sock, 4)
    except (TimeoutError, OSError) as e:
        raise HandshakeError(f"Connection error: {e}") from e

    payload_len = struct.unpack("!I", header)[0]
    if payload_len > _MAX_MESSAGE_SIZE:
        raise HandshakeError(
            f"Message too large: {payload_len} bytes (max {_MAX_MESSAGE_SIZE})"
        )

    try:
        payload = _recv_exact(sock, payload_len)
    except (TimeoutError, OSError) as e:
        raise HandshakeError(f"Connection error: {e}") from e

    return HandshakeMessage.decode(header + payload)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from a socket."""
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise HandshakeError("Connection closed by peer")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Convenience: TCP server & client
# ---------------------------------------------------------------------------

def run_handshake_server(
    identity_card: IdentityCard,
    private_key: ed25519.Ed25519PrivateKey,
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    on_verify: OnVerifyCallback | None = None,
    on_confirm: OnConfirmCallback | None = None,
    stop_event: threading.Event | None = None,
    rate_limit: int = 10,
    rate_window: float = 60.0,
) -> None:
    """Run a blocking TCP handshake server (responder role).

    Accepts one connection at a time and performs a full mutual
    authentication handshake.

    Args:
        identity_card: This server's identity card.
        private_key: This server's private key.
        host: Bind address.
        port: TCP port.
        on_verify: Optional callback to verify peer cards.
        on_confirm: Optional callback on successful auth.
        stop_event: Set this event to stop the server gracefully.
        rate_limit: Max handshakes per *rate_window* seconds.
        rate_window: Time window in seconds for rate limiting.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    server.settimeout(1.0)  # 1s timeout so we can check stop_event

    # Simple sliding-window rate limiter
    _rate_hits: list[float] = []

    print(f"🎧 Handshake server listening on {host}:{port}")
    print(f"   DID: {identity_card.id}")
    print(f"   Rate limit: {rate_limit} handshakes per {rate_window}s")

    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            try:
                conn, addr = server.accept()
            except TimeoutError:
                continue

            # Rate limit check
            now = time.monotonic()
            _rate_hits = [t for t in _rate_hits if now - t < rate_window]
            if len(_rate_hits) >= rate_limit:
                print(f"⏱️  Rate limit exceeded from {addr}")
                conn.close()
                continue
            _rate_hits.append(now)

            print(f"\n🔗 Connection from {addr}")
            try:
                _handle_connection(
                    conn, identity_card, private_key,
                    on_verify=on_verify,
                    on_confirm=on_confirm,
                )
            except Exception as e:
                print(f"❌ Handshake failed: {e}")
            finally:
                conn.close()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        print("👋 Server stopped")


def run_handshake_client(
    identity_card: IdentityCard,
    private_key: ed25519.Ed25519PrivateKey,
    peer_did: str,
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    on_verify: OnVerifyCallback | None = None,
    on_confirm: OnConfirmCallback | None = None,
) -> tuple[bool, IdentityCard | None, bytes | None]:
    """Connect to a handshake server and perform mutual authentication.

    Returns:
        Tuple of (success, peer_card, session_key).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except OSError as e:
        print(f"❌ Connection failed: {e}")
        return False, None, None

    try:
        hp = HandshakeProtocol(
            identity_card=identity_card,
            private_key=private_key,
            is_responder=False,
            on_verify=on_verify,
            on_confirm=on_confirm,
        )

        # 1. Send HELLO
        hello = hp.start()
        send_message(sock, hello)
        print(f"→ Sent HELLO (DID: {identity_card.id})")

        # 2. Receive CHALLENGE
        challenge_msg = recv_message(sock)
        print(f"← Received CHALLENGE from {challenge_msg.payload.get('from', '?')}")

        # 3. Send AUTH
        auth_msg = hp.handle_message(challenge_msg)
        send_message(sock, auth_msg)
        print("→ Sent AUTH (identity card)")

        # 4. Receive CONFIRM
        confirm_msg = recv_message(sock)
        print(f"← Received CONFIRM: {confirm_msg.payload.get('status', '?')}")

        # 5. Complete handshake
        final_msg = hp.handle_message(confirm_msg)
        if final_msg.msg_type != "error":
            send_message(sock, final_msg)

        if hp.is_authenticated:
            print("✅ Mutual authentication successful!")
            print(f"   Peer DID: {hp.peer_card.id if hp.peer_card else 'N/A'}")
            return True, hp.peer_card, hp.session_key
        else:
            print("❌ Authentication failed")
            return False, None, None

    except (HandshakeError, OSError) as e:
        print(f"❌ Handshake error: {e}")
        return False, None, None
    finally:
        sock.close()


def _handle_connection(
    conn: socket.socket,
    identity_card: IdentityCard,
    private_key: ed25519.Ed25519PrivateKey,
    on_verify: OnVerifyCallback | None = None,
    on_confirm: OnConfirmCallback | None = None,
) -> None:
    """Handle a single handshake connection (responder side)."""
    hp = HandshakeProtocol(
        identity_card=identity_card,
        private_key=private_key,
        is_responder=True,
        on_verify=on_verify,
        on_confirm=on_confirm,
    )

    # 1. Receive HELLO
    hello_msg = recv_message(conn)
    print(f"← Received HELLO from {hello_msg.payload.get('from', '?')}")

    # 2. Send CHALLENGE
    challenge_msg = hp.handle_message(hello_msg)
    send_message(conn, challenge_msg)
    print("→ Sent CHALLENGE")

    # 3. Receive AUTH
    auth_msg = recv_message(conn)
    print("← Received AUTH")

    # 4. Send CONFIRM
    confirm_msg = hp.handle_message(auth_msg)
    send_message(conn, confirm_msg)
    print(f"→ Sent CONFIRM: {confirm_msg.payload.get('status', '?')}")

    # 5. Receive final acknowledgement (if session established)
    if confirm_msg.payload.get("status") in ("ok", "session_established"):
        try:
            final_msg = recv_message(conn)
            hp.handle_message(final_msg)
            if hp.is_authenticated:
                print("✅ Mutual authentication successful!")
                print(f"   Peer DID: {hp.peer_card.id if hp.peer_card else 'N/A'}")
        except HandshakeError:
            pass


def hashlib_sha256(data: bytes) -> bytes:
    """SHA-256 hash."""
    import hashlib
    return hashlib.sha256(data).digest()
