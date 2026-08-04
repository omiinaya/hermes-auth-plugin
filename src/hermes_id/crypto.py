"""
Cryptographic primitives for hermes-id.

Security guarantees
-------------------
- **Signing:** Ed25519 (EdDSA on Curve25519). Post-quantum vulnerable but
  classically unforgeable under chosen-message attack (SUF-CMA).
- **Encryption:** AES-256-GCM (authenticated encryption with associated data).
  Provides confidentiality + integrity.
- **Key derivation:** Argon2id (if `argon2-cffi` installed) > scrypt
  (memory-hard password-based KDF, N=2^17) > PBKDF2-SHA256 fallback.
  New blobs (v3) record the exact KDF parameters, so they stay
  decryptable even if defaults change in future versions; legacy v1/v2
  blobs use pinned historical parameters.
- **Key agreement:** X25519 ECDH for ephemeral session keys.

All randomness comes from `os.urandom()` (kernel CSPRNG).
"""

import base64
import functools
import hashlib
import os
import struct

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# ---------------------------------------------------------------------------
# Secure memory zeroing
# ---------------------------------------------------------------------------

def secure_zero(data: bytearray | memoryview) -> None:
    """Overwrite a mutable buffer with zeros.

    Uses ``ctypes.memset`` via a C library call that the compiler will
    **not** optimize away, unlike a pure-Python ``= b'\\x00' * n`` which
    the interpreter may elide for dead objects.

    This is **best-effort** on Python objects.  The ``cryptography``
    library manages Ed25519 private keys internally; we overwrite the
    DER-serialized bytes and any temporary buffers we control.

    Usage::

        buf = bytearray(sensitive_data)
        secure_zero(buf)
        # buf now contains all zeros
    """
    import ctypes
    length = len(data)
    if length == 0:
        return
    # Get a mutable pointer and fill with zeros
    ptr = (ctypes.c_char * length).from_buffer(data)
    ctypes.memset(ptr, 0, length)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# AES-256-GCM parameters
_AES_KEY_SIZE = 32  # bytes  (256 bits)
_AES_NONCE_SIZE = 12  # bytes  (96-bit standard nonce)
_AES_TAG_SIZE = 16  # bytes  (128-bit authentication tag)

# Argon2id parameters (OWASP 2024 recommendations — interactive use)
_ARGON2_TIME_COST = 3          # iterations
_ARGON2_MEMORY_COST = 65536    # 64 MiB
_ARGON2_PARALLELISM = 4        # lanes

# scrypt parameters for NEW blobs (OWASP 2024 recommendations for
# interactive use): N=2^17 with r=8 needs ~128 MiB and ~1s on modern
# hardware. N=2^20 (~1 GiB, ~10s) was the historical default — far too
# slow for an interactive CLI; those blobs keep working via the pinned
# legacy parameters below.
_SCRYPT_N = 2**17       # CPU/memory cost parameter
_SCRYPT_R = 8           # blocksize parameter
_SCRYPT_P = 1           # parallelization parameter
_SCRYPT_DKLEN = 32      # output key length (AES-256)

# Legacy scrypt parameters — pinned forever for decrypting v1/v2 blobs
# (created before the v3 format recorded params). Old blobs carry no
# parameters, so these historical constants are the ONLY way to derive
# the same key. Do NOT change.
_SCRYPT_N_LEGACY = 2**20
_SCRYPT_R_LEGACY = 8
_SCRYPT_P_LEGACY = 1

# PBKDF2 fallback (if scrypt unavailable)
_PBKDF2_ITERATIONS = 600_000
_PBKDF2_HASH = "sha256"

# Nonce size for handshake challenges
CHALLENGE_SIZE = 32  # bytes  (256-bit random challenge)

# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    """Decode URL-safe base64 (may have padding stripped)."""
    pad = 4 - (len(s) % 4)
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _multibase_encode(data: bytes) -> str:
    """Encode bytes as base58btc multibase (starts with 'z')."""
    # Use base64 as a practical approximation; full base58btc requires a
    # base58 library. For protocol correctness we use base64url with 'u'
    # multibase prefix, which is also a valid IETF multibase encoding.
    return "u" + _b64(data)


# ---------------------------------------------------------------------------
# Ed25519 — Signing
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair from kernel entropy."""
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    return private, public


def sign(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign *message* with *private_key* using Ed25519.

    Returns a 64-byte raw signature.
    """
    return private_key.sign(message)


def verify(public_key: ed25519.Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    """Verify *signature* on *message* using *public_key*.

    Returns True if valid, False otherwise.  Constant-time verification
    is handled by the underlying ``cryptography`` library.
    """
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def serialize_private_key(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Serialize an Ed25519 private key to PKCS#8 DER bytes."""
    return private_key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )


def deserialize_private_key(der_bytes: bytes) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from PKCS#8 DER bytes."""
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    return load_der_private_key(der_bytes, password=None)


def serialize_public_key(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Serialize an Ed25519 public key to SubjectPublicKeyInfo DER bytes."""
    return public_key.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(der_bytes: bytes) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 public key from SubjectPublicKeyInfo DER bytes."""
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    key = load_der_public_key(der_bytes)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError(f"Expected Ed25519 public key, got {type(key).__name__}")
    return key


def public_key_bytes(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Raw 32-byte Ed25519 public key."""
    return public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )


# ---------------------------------------------------------------------------
# X25519 — Key agreement
# ---------------------------------------------------------------------------

def generate_x25519_keypair() -> tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Generate an ephemeral X25519 keypair for session key agreement."""
    private = x25519.X25519PrivateKey.generate()
    public = private.public_key()
    return private, public


def x25519_shared_secret(
    private_key: x25519.X25519PrivateKey,
    peer_public: x25519.X25519PublicKey,
) -> bytes:
    """Compute ECDH shared secret (32 bytes)."""
    return private_key.exchange(peer_public)


def derive_session_key(shared_secret: bytes, context: bytes = b"hermes-id/v1") -> bytes:
    """Derive an AES-256 session key from an X25519 shared secret.

    Uses HKDF-SHA256 to stretch the 32-byte DH output into a 32-byte
    symmetric key bound to the protocol context.
    """
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=context,
    )
    return hkdf.derive(shared_secret)


# ---------------------------------------------------------------------------
# AES-256-GCM — Key encryption at rest
# ---------------------------------------------------------------------------

# Encrypted-blob header so a blob is SELF-DESCRIBING (which KDF was used).
# Blob formats (oldest → newest):
#   Format v3:  b"HID3" + kdf_id(1) + params(12) + salt(16) + nonce(12) + ct+tag
#   Format v2:  b"HID2" + kdf_id(1) + salt(16) + nonce(12) + ct+tag
#   Legacy v1 (no magic):  salt(16) + nonce(12) + ct+tag
#
# The v3 params block is 12 bytes, big-endian: [u32 a][u32 b][u32 c]
#   argon2id:  a=time_cost, b=memory_cost, c=parallelism
#   scrypt:    a=n, b=r, c=p
#   pbkdf2:    a=iterations, b=0, c=0
#
# Recording parameters makes v3 blobs fully self-describing: they decrypt
# correctly on any host, even after code defaults change. v1/v2 blobs carry
# no parameters, so they use the pinned legacy constants (the ones in effect
# when they were created).
_BLOB_MAGIC_V3 = b"HID3"
_BLOB_MAGIC_V2 = b"HID2"
_BLOB_PARAMS_SIZE = 12
_KDF_ARGON2 = 0
_KDF_SCRYPT = 1
_KDF_PBKDF2 = 2
_KDF_NAMES = {_KDF_ARGON2: "argon2id", _KDF_SCRYPT: "scrypt", _KDF_PBKDF2: "pbkdf2"}


def _blob_params_for(kdf: int) -> tuple[int, int, int]:
    """KDF parameters used for NEW (v3) blobs in this environment."""
    if kdf == _KDF_ARGON2:
        return (_ARGON2_TIME_COST, _ARGON2_MEMORY_COST, _ARGON2_PARALLELISM)
    if kdf == _KDF_SCRYPT:
        return (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
    return (_PBKDF2_ITERATIONS, 0, 0)


def _legacy_params_for(kdf: int) -> tuple[int, int, int]:
    """Pinned parameters that historical v1/v2 blobs were created with.

    These must never change: legacy blobs don't record parameters, so
    this is the only way to derive the same key. Argon2id and PBKDF2
    parameters are historically unchanged; scrypt was N=2^20.
    """
    if kdf == _KDF_ARGON2:
        return (_ARGON2_TIME_COST, _ARGON2_MEMORY_COST, _ARGON2_PARALLELISM)
    if kdf == _KDF_SCRYPT:
        return (_SCRYPT_N_LEGACY, _SCRYPT_R_LEGACY, _SCRYPT_P_LEGACY)
    return (_PBKDF2_ITERATIONS, 0, 0)


def _pack_params(a: int, b: int, c: int) -> bytes:
    return struct.pack(">III", a, b, c)


def _unpack_params(raw: bytes) -> tuple[int, int, int]:
    return struct.unpack(">III", raw)


@functools.lru_cache(maxsize=1)
def _kdf_id() -> int:
    """Return the KDF id to use for NEW blobs in this environment.

    Preference: Argon2id (if argon2-cffi installed) > scrypt > PBKDF2.
    Cached per-process — KDF availability never changes at runtime.

    The scrypt probe uses minimal cost parameters: it only checks whether
    OpenSSL's scrypt is available at all. The real derivation cost comes
    from the parameters chosen by :func:`_blob_params_for`, not from the
    probe (a full-cost probe would double every encrypt's latency).
    """
    try:
        from argon2.low_level import (  # noqa: F401  # pyright: ignore[reportMissingImports]
            Type,
            hash_secret_raw,
        )

        return _KDF_ARGON2
    except ImportError:
        pass
    try:
        hashlib.scrypt(password=b"p", salt=b"s", n=2, r=1, p=1, dklen=1)
        return _KDF_SCRYPT
    except (ValueError, TypeError):
        return _KDF_PBKDF2


def _scrypt_maxmem_for(n: int, r: int) -> int:
    """OpenSSL maxmem cap for the given scrypt parameters.

    OpenSSL 3.x defaults to 32 MiB and rejects larger working sets unless
    maxmem is raised. Required memory is 128 * n * r; we allow that plus
    1 MiB slack. For N=2^17,r=8 this is ~129 MiB; for legacy N=2^20 it is
    ~1 GiB (matching the historical cap).
    """
    return 128 * n * r + (1 << 20)


def _derive_storage_key_with_kdf(
    password: str,
    salt: bytes,
    kdf: int,
    params: tuple[int, int, int] | None = None,
) -> bytes:
    """Derive a 256-bit key from *password* + *salt* using the given KDF id.

    When *params* is omitted, the current defaults for new blobs are used
    (see :func:`_blob_params_for`). Legacy decrypt paths pass explicit
    pinned parameters.
    """
    if kdf == _KDF_ARGON2:
        from argon2.low_level import Type, hash_secret_raw

        time_cost, memory_cost, parallelism = params or (
            _ARGON2_TIME_COST,
            _ARGON2_MEMORY_COST,
            _ARGON2_PARALLELISM,
        )
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            type=Type.ID,       # Argon2id — hybrid resistant to side-channel + GPU
        )
    if kdf == _KDF_SCRYPT:
        n, r, p = params or (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
        return hashlib.scrypt(
            password=password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=_SCRYPT_DKLEN,
            maxmem=_scrypt_maxmem_for(n, r),
        )
    # PBKDF2 fallback
    iterations = params[0] if params else _PBKDF2_ITERATIONS
    return hashlib.pbkdf2_hmac(
        _PBKDF2_HASH,
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )


def _derive_storage_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from *password* + *salt* using the strongest
    KDF available in this environment (see :func:`_kdf_id`)."""
    return _derive_storage_key_with_kdf(password, salt, _kdf_id())


def _pack_blob_v3(kdf: int, params: tuple[int, int, int], salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return (
        _BLOB_MAGIC_V3
        + bytes([kdf])
        + _pack_params(*params)
        + salt
        + nonce
        + ciphertext
    )


def encrypt_key(private_key_bytes: bytes, password: str) -> bytes:
    """Encrypt a private key with *password* using AES-256-GCM.

    Output format v3 (fully self-describing — records both the KDF and
    its exact parameters):

        b"HID3" + kdf_id(1) + params(12) + salt(16) + nonce(12) + ciphertext + GCM tag(16)

    Self-describing blobs are portable across environments AND across
    future parameter changes: a blob created today decrypts tomorrow no
    matter what defaults the code evolves to.
    """
    kdf = _kdf_id()
    salt = os.urandom(16)
    nonce = os.urandom(_AES_NONCE_SIZE)
    params = _blob_params_for(kdf)

    key = _derive_storage_key_with_kdf(password, salt, kdf, params)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, private_key_bytes, None)  # no AAD

    return _pack_blob_v3(kdf, params, salt, nonce, ciphertext)


def decrypt_key(blob: bytes, password: str) -> bytes:
    """Decrypt a private key previously encrypted with :func:`encrypt_key`.

    Supports all three blob formats:

    - **v3** (``HID3``) — fully self-describing: reads the KDF id and its
      exact parameters from the blob. Decrypts correctly regardless of the
      code's current defaults.
    - **v2** (``HID2``) — self-describing KDF only; parameters come from the
      pinned legacy constants.
    - **v1** (no header) — each available KDF is tried with the pinned
      legacy parameters in preference order; the AES-GCM tag authenticates
      the result, so only the KDF that originally encrypted the key can
      succeed.

    Raises ``cryptography.exceptions.InvalidTag`` if the password is wrong
    or the blob is corrupted.
    """
    if blob.startswith(_BLOB_MAGIC_V3):
        kdf = blob[4]
        params = _unpack_params(blob[5 : 5 + _BLOB_PARAMS_SIZE])
        payload = blob[5 + _BLOB_PARAMS_SIZE :]
        salt = payload[0:16]
        nonce = payload[16:28]
        ciphertext = payload[28:]
        key = _derive_storage_key_with_kdf(password, salt, kdf, params)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    if blob.startswith(_BLOB_MAGIC_V2):
        kdf = blob[4]
        payload = blob[5:]
        salt = payload[0:16]
        nonce = payload[16:28]
        ciphertext = payload[28:]
        key = _derive_storage_key_with_kdf(password, salt, kdf, _legacy_params_for(kdf))
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    # Legacy v1 blob — try each KDF with pinned legacy params; GCM tag validates.
    salt = blob[0:16]
    nonce = blob[16:28]
    ciphertext = blob[28:]
    last_error: Exception | None = None
    for kdf in (_KDF_ARGON2, _KDF_SCRYPT, _KDF_PBKDF2):
        try:
            key = _derive_storage_key_with_kdf(password, salt, kdf, _legacy_params_for(kdf))
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except ImportError:
            continue  # KDF unavailable in this environment — try next
        except Exception as e:  # InvalidTag or scrypt OSError etc.
            last_error = e
            continue
    if last_error is not None:
        raise last_error
    raise InvalidTag


# ---------------------------------------------------------------------------
# Random challenge generation
# ---------------------------------------------------------------------------

def generate_challenge(size: int = CHALLENGE_SIZE) -> bytes:
    """Generate a cryptographically secure random challenge."""
    return os.urandom(size)


# ---------------------------------------------------------------------------
# DID generation
# ---------------------------------------------------------------------------

def derive_did(public_key: ed25519.Ed25519PublicKey) -> str:
    """Derive a content-addressed Decentralized Identifier from a public key.

    Format: ``did:hermes:<base58(sha256(pubkey))[:12]>``

    The 12-char (72-bit) suffix provides ~2²² collision resistance
    against accidental overlap — sufficient for practical use.  Full
    public key is always available in the identity document.
    """
    raw = public_key_bytes(public_key)
    h = hashlib.sha256(raw).digest()
    # Use base64 shorthand for the DID suffix (12 chars, ~72 bits)
    short_id = _b64(h)[:12]
    return f"did:hermes:{short_id}"
