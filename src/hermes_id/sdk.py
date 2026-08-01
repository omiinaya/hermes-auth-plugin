"""
hermes-id App-Side SDK — offline-first verification for every app type.

This module is the consumable foundation for integrating any spacetime-x
project (FastAPI service, CLI tool, cron job, browser backend, headless
daemon) with the hermes-id Auth Server.

Design principles (verified 2026-07-30, gaps closed in v1.3.0):

1. **Offline-first** — at startup (or first verify) the SDK fetches the auth
   server's identity card once and caches it to disk. Every token is then
   verified *locally*: Ed25519 signature against the cached card, ``aud``
   matches this project, expiry check. No per-request round-trip, and apps
   keep working when the auth server is down.

2. **Audience enforcement** — ``verify_token_offline(..., project=...)``
   rejects any token whose ``aud`` does not match the project name. A token
   minted for ``spacetime-tv`` is worthless on ``spacetime-air``.

3. **Works for every app type** — ``verify_token_offline()`` is a pure,
   FastAPI-free function for CLI tools, scripts, cron jobs. The FastAPI
   dependency lives in ``hermes_id.fastapi_middleware``.

4. **Best-effort online revocation** — :class:`RevocationChecker` asks the
   auth server whether a token has been revoked and caches the answer
   briefly. When the server is unreachable it fails **open** (signature +
   expiry + audience were already validated locally), never fails closed.

Usage (CLI / cron / script)::

    from hermes_id.sdk import load_server_card, verify_token_offline

    card = load_server_card("http://192.168.1.10:9488")
    payload = verify_token_offline(token, card, project="spacetime-code")
    if payload is None:
        sys.exit("invalid token")

Usage (FastAPI): see ``hermes_id.fastapi_middleware.HermesIDAuth``.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from hermes_id.crypto import _unb64
from hermes_id.identity import IdentityCard, verify_identity_card

# ---------------------------------------------------------------------------
# Constants / env contract
# ---------------------------------------------------------------------------

ENV_SERVER_URL = "HERMES_AUTH_SERVER_URL"
ENV_PROJECT = "HERMES_AUTH_PROJECT"

_DEFAULT_CARD_MAX_AGE = 3600.0      # refresh cached server card after 1h
_DEFAULT_REVOCATION_TTL = 300.0     # cache revocation answers for 5 min
_DEFAULT_TIMEOUT = 5.0              # online calls never block longer than this
_DEFAULT_CARD_CACHE_DIR = "~/.hermes/auth"
_TOKEN_CACHE_DIR = "~/.hermes/auth-tokens"

_MULTIBASE_BASE64URL_PREFIX = "u"


class AuthError(Exception):
    """Raised when token verification fails.

    ``reason`` is a stable machine-readable code: ``invalid``, ``revoked``,
    ``untrusted_server``.
    """

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason


# ---------------------------------------------------------------------------
# Pure offline verification (FastAPI-free)
# ---------------------------------------------------------------------------

def _card_public_key_bytes(card: IdentityCard) -> bytes | None:
    """Extract the raw Ed25519 public key bytes from an identity card."""
    pub_b64 = card.public_key_multibase
    if not pub_b64:
        return None
    if pub_b64.startswith(_MULTIBASE_BASE64URL_PREFIX):
        pub_b64 = pub_b64[1:]
    try:
        return _unb64(pub_b64)
    except Exception:
        return None


def verify_token_offline(
    token: str,
    server_card: IdentityCard | dict[str, Any] | str,
    project: str | None = None,
    now: float | None = None,
) -> dict[str, Any] | None:
    """Verify a signed auth token entirely locally.

    Checks, in order:

    1. Token shape — ``base64url(payload).base64url(signature)``.
    2. Ed25519 signature against the auth server's identity card.
    3. Expiry — ``expires_at`` must be in the future.
    4. Audience — if ``project`` is given, ``payload["aud"]`` must equal it.
       A token with a mismatched (or missing, when the app is scoped) audience
       is rejected.

    Args:
        token: The signed auth token string.
        server_card: The auth server's ``IdentityCard``, its dict form (e.g.
            from :func:`load_server_card`), or a raw JSON string (e.g. a card
            file read from disk).
        project: Expected audience. Pass your project name to enforce the
            audience check; pass ``None`` to skip it (not recommended).
        now: Override "current time" (unix seconds) for tests.

    Returns:
        The token payload dict if valid, ``None`` otherwise.
    """
    if isinstance(server_card, str):
        try:
            server_card = IdentityCard.from_json(server_card)
        except Exception:
            return None
    if isinstance(server_card, dict):
        try:
            server_card = IdentityCard.from_json(json.dumps(server_card))
        except Exception:
            return None

    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig_b64 = parts
        payload_bytes = _unb64(payload_b64)
        signature_bytes = _unb64(sig_b64)
    except Exception:
        return None

    pub_raw = _card_public_key_bytes(server_card)
    if pub_raw is None:
        return None

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
        try:
            public_key.verify(signature_bytes, payload_bytes)
        except InvalidSignature:
            return None
    except Exception:
        return None

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return None

    now = now if now is not None else time.time()
    if payload.get("expires_at", 0) < now:
        return None

    # Audience enforcement — the P2 security fix
    if project and payload.get("aud", "") != project:
        return None

    return payload


# ---------------------------------------------------------------------------
# Server identity card loading + disk caching
# ---------------------------------------------------------------------------

def default_card_cache_path(server_url: str, cache_dir: str | None = None) -> Path:
    """Compute the default on-disk cache location for a server's card."""
    import hashlib

    base = Path(cache_dir or _DEFAULT_CARD_CACHE_DIR).expanduser()
    slug = hashlib.sha256(server_url.encode("utf-8")).hexdigest()[:16]
    return base / f"server-card-{slug}.json"


def load_server_card(
    server_url: str,
    cache_path: str | Path | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
    max_age: float = _DEFAULT_CARD_MAX_AGE,
    allow_stale: bool = True,
    verify: bool | str = True,
) -> dict[str, Any]:
    """Fetch and verify the auth server's identity card, caching it to disk.

    Strategy:
    - If a fresh-enough cache exists, load + re-verify its self-signature.
    - Otherwise ``GET {server_url}/identity``, verify the card's
      self-signature and DID, then persist it.
    - If the server is unreachable but a (possibly stale) cache exists and
      ``allow_stale`` is True, use the stale card — the app keeps working
      offline. The self-signature is still checked on every load.

    Args:
        server_url: Base URL of the hermes-id Auth Server.
        cache_path: Disk cache location. Defaults to
            ``~/.hermes/auth/server-card-<hash>.json``.
        timeout: HTTP timeout in seconds.
        max_age: Seconds before a cached card is considered stale and
            re-fetched (default 3600).
        allow_stale: If True, fall back to a stale cached card when the
            server is unreachable.
        verify: TLS verification — True (default), a CA bundle path, or
            False to disable (self-signed testing only).

    Returns:
        The server identity card as a dict (JSON-serializable).

    Raises:
        AuthError: if no card can be obtained and no stale cache exists, or
            the card's self-signature fails.
    """
    try:
        import httpx
    except ImportError as e:  # pragma: no cover
        raise AuthError("untrusted_server", "httpx is required to fetch the server card") from e

    # TLS verification: explicit arg > HERMES_AUTH_VERIFY env > default True
    if verify is True and os.environ.get("HERMES_AUTH_VERIFY"):
        env_verify = os.environ["HERMES_AUTH_VERIFY"].strip().lower()
        if env_verify in ("false", "0", "no"):
            verify = False
        elif env_verify in ("true", "1", "yes"):
            verify = True
        else:
            verify = env_verify  # CA bundle path

    cache_file = Path(cache_path) if cache_path else default_card_cache_path(server_url)

    def _load_cache() -> dict[str, Any] | None:
        try:
            if not cache_file.exists():
                return None
            raw = cache_file.read_text()
            data = json.loads(raw)
            card = IdentityCard.from_json(raw)
            if not verify_identity_card(card):
                return None
            return data
        except Exception:
            return None

    def _fetch() -> dict[str, Any]:
        try:
            resp = httpx.get(f"{server_url.rstrip('/')}/identity", timeout=timeout, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            card = IdentityCard.from_json(json.dumps(data))
            if not verify_identity_card(card):
                raise AuthError(
                    "untrusted_server",
                    "Server identity card failed self-signature verification",
                )
            try:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps(data, indent=2))
            except OSError:
                pass  # cache is best-effort; never fail auth because of disk
            return data
        except AuthError:
            raise
        except Exception as e:
            raise AuthError("untrusted_server", f"Cannot fetch server identity card: {e}") from e

    # 1. Fresh-enough cache?
    cached = _load_cache()
    if cached is not None:
        try:
            mtime = cache_file.stat().st_mtime
            if time.time() - mtime < max_age:
                return cached
        except OSError:
            pass

    # 2. Try the network
    try:
        return _fetch()
    except AuthError:
        if cached is not None and allow_stale:
            return cached
        raise


# ---------------------------------------------------------------------------
# Best-effort online revocation checker
# ---------------------------------------------------------------------------

class RevocationChecker:
    """Checks token revocation against the auth server, caching answers.

    Fails **open**: if the server is unreachable, the token is treated as
    not-revoked (signature/expiry/audience were already validated offline).
    Revocation answers are cached for ``ttl`` seconds per token_id to avoid
    hammering the server on every request.
    """

    def __init__(
        self,
        server_url: str,
        ttl: float = _DEFAULT_REVOCATION_TTL,
        timeout: float = _DEFAULT_TIMEOUT,
        verify: bool | str = True,
    ):
        self._server_url = server_url.rstrip("/")
        self._ttl = ttl
        self._timeout = timeout
        self._verify = verify
        self._cache: dict[str, tuple[bool, float]] = {}  # token_id -> (revoked, checked_at)

    def is_revoked(self, token: str, token_id: str) -> bool:
        """Return True if the token has been revoked.

        A server-side ``valid=False`` while the local (offline) checks passed
        means the token was revoked. Network failure ⇒ False (fail-open).
        """
        if not token_id:
            return False  # cannot blacklist a token without an id
        now = time.time()
        cached = self._cache.get(token_id)
        if cached and now - cached[1] < self._ttl:
            return cached[0]

        try:
            import httpx

            resp = httpx.post(
                f"{self._server_url}/verify",
                json={"token": token},
                timeout=self._timeout,
                verify=self._verify,
            )
            resp.raise_for_status()
            data = resp.json()
            revoked = not bool(data.get("valid"))
        except Exception:
            revoked = False  # fail-open when the auth server is unreachable

        self._cache[token_id] = (revoked, now)
        return revoked


# ---------------------------------------------------------------------------
# Per-project token cache (runtime seamlessness for agents)
# ---------------------------------------------------------------------------

class TokenCache:
    """Persistent per-project auth token cache.

    Stores the latest token for a project at
    ``~/.hermes/auth-tokens/<project>.json`` so a Hermes agent (or any
    script) can present a valid token without re-running the challenge flow
    on every invocation. ``get_or_login`` transparently refreshes before
    expiry and re-authenticates when needed.
    """

    def __init__(self, project: str, directory: str | None = None):
        if not project:
            raise ValueError("TokenCache requires a project name")
        self._project = project
        base = Path(directory or _TOKEN_CACHE_DIR).expanduser()
        self._path = base / f"{project}.json"

    @property
    def path(self) -> Path:
        """Absolute path of the cache file."""
        return self._path

    def get(self) -> tuple[str, dict[str, Any]] | None:
        """Return ``(token, payload)`` from cache, or None."""
        try:
            if not self._path.exists():
                return None
            data = json.loads(self._path.read_text())
            token = data.get("token", "")
            payload = data.get("payload", {})
            if not token:
                return None
            return token, payload
        except Exception:
            return None

    def put(self, token: str, payload: dict[str, Any]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(
                    {"token": token, "payload": payload, "saved_at": time.time()},
                    indent=2,
                )
            )
        except OSError:
            pass

    def clear(self) -> None:
        import contextlib

        with contextlib.suppress(OSError):
            self._path.unlink(missing_ok=True)


__all__ = [
    "AuthError",
    "ENV_SERVER_URL",
    "ENV_PROJECT",
    "TokenCache",
    "RevocationChecker",
    "default_card_cache_path",
    "load_server_card",
    "verify_token_offline",
]
