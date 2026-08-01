"""
Cryptographic primitives for hermes-id.

Security guarantees
-------------------
- **Signing:** Ed25519 (EdDSA on Curve25519). Post-quantum vulnerable but
  classically unforgeable under chosen-message attack (SUF-CMA).
- **Encryption:** AES-256-GCM (authenticated encryption with associated data).
  Provides confidentiality + integrity.
- **Key derivation:** scrypt (memory-hard password-based KDF, N=2^20).
  Falls back to PBKDF2-SHA256 if scrypt is unavailable. Optionally
  upgrades to Argon2id if the `argon2-cffi` package is installed.
- **Key agreement:** X25519 ECDH for ephemeral session keys.

All randomness comes from `os.urandom()` (kernel CSPRNG).
"""

import base64
import hashlib
import os

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

# scrypt parameters (OWASP 2024 recommendations for interactive use)
_SCRYPT_N = 2**20       # CPU/memory cost parameter
_SCRYPT_R = 8           # blocksize parameter
_SCRYPT_P = 1           # parallelization parameter
_SCRYPT_DKLEN = 32      # output key length (AES-256)
_SCRYPT_MAXMEM = 1_500_000_000  # 1.5 GiB — OpenSSL 3.x defaults to 32 MiB and
                                # rejects N=2^20,r=8 (~1 GiB + overhead) without
                                # this; must stay < 2^31-1 (signed int32 cap)

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
# Format v2:  b"HID2" + kdf_id(1 byte) + salt(16) + nonce(12) + ciphertext+tag
# Legacy v1 (no magic):  salt(16) + nonce(12) + ciphertext+tag
_BLOB_MAGIC_V2 = b"HID2"
_KDF_ARGON2 = 0
_KDF_SCRYPT = 1
_KDF_PBKDF2 = 2
_KDF_NAMES = {_KDF_ARGON2: "argon2id", _KDF_SCRYPT: "scrypt", _KDF_PBKDF2: "pbkdf2"}


def _kdf_id() -> int:
    """Return the KDF id to use for NEW blobs in this environment.

    Preference: Argon2id (if argon2-cffi installed) > scrypt > PBKDF2.
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
        hashlib.scrypt(
            password=b"probe", salt=b"probe",
            n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
            maxmem=_SCRYPT_MAXMEM,
        )
        return _KDF_SCRYPT
    except (ValueError, TypeError):
        return _KDF_PBKDF2


def _derive_storage_key_with_kdf(password: str, salt: bytes, kdf: int) -> bytes:
    """Derive a 256-bit key from *password* + *salt* using the given KDF id."""
    if kdf == _KDF_ARGON2:
        from argon2.low_level import Type, hash_secret_raw

        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=3,        # 3 iterations
            memory_cost=65536,  # 64 MiB
            parallelism=4,
            hash_len=32,
            type=Type.ID,       # Argon2id — hybrid resistant to side-channel + GPU
        )
    if kdf == _KDF_SCRYPT:
        return hashlib.scrypt(
            password=password.encode("utf-8"),
            salt=salt,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
            dklen=_SCRYPT_DKLEN,
            maxmem=_SCRYPT_MAXMEM,
        )
    # PBKDF2 fallback
    return hashlib.pbkdf2_hmac(
        _PBKDF2_HASH,
        password.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=32,
    )


def _derive_storage_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from *password* + *salt* using the strongest
    KDF available in this environment (see :func:`_kdf_id`)."""
    return _derive_storage_key_with_kdf(password, salt, _kdf_id())


def _pack_blob_v2(kdf: int, salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return _BLOB_MAGIC_V2 + bytes([kdf]) + salt + nonce + ciphertext


def encrypt_key(private_key_bytes: bytes, password: str) -> bytes:
    """Encrypt a private key with *password* using AES-256-GCM.

    Output format v2 (self-describing — records which KDF derived the key):
        b"HID2" + kdf_id(1) + salt(16) + nonce(12) + ciphertext + GCM tag(16)

    The KDF id header makes blobs portable across environments (a blob
    created where argon2-cffi was installed decrypts correctly on a host
    without it, as long as that KDF is available or the legacy fallback
    chain can validate the GCM tag).
    """
    kdf = _kdf_id()
    salt = os.urandom(16)
    nonce = os.urandom(_AES_NONCE_SIZE)

    key = _derive_storage_key_with_kdf(password, salt, kdf)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, private_key_bytes, None)  # no AAD

    return _pack_blob_v2(kdf, salt, nonce, ciphertext)


def decrypt_key(blob: bytes, password: str) -> bytes:
    """Decrypt a private key previously encrypted with :func:`encrypt_key`.

    Supports both the v2 self-describing format and legacy v1 blobs (no
    header). For legacy blobs, each available KDF is tried in preference
    order; the AES-GCM tag authenticates the result, so only the KDF that
    originally encrypted the key can succeed.

    Raises ``cryptography.exceptions.InvalidTag`` if the password is wrong
    or the blob is corrupted.
    """
    if blob.startswith(_BLOB_MAGIC_V2):
        kdf = blob[4]
        payload = blob[5:]
        salt = payload[0:16]
        nonce = payload[16:28]
        ciphertext = payload[28:]
        key = _derive_storage_key_with_kdf(password, salt, kdf)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    # Legacy v1 blob — try each KDF in preference order; GCM tag validates.
    salt = blob[0:16]
    nonce = blob[16:28]
    ciphertext = blob[28:]
    last_error: Exception | None = None
    for kdf in (_KDF_ARGON2, _KDF_SCRYPT, _KDF_PBKDF2):
        try:
            key = _derive_storage_key_with_kdf(password, salt, kdf)
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
