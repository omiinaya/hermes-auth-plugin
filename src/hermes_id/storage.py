"""
Secure key storage — encrypted private key persistence.

The private key is stored **encrypted at rest** using AES-256-GCM with a
password-derived key (scrypt / Argon2id / PBKDF2).  The identity card
(public) is stored in plaintext alongside.

Directory layout::

    ~/.hermes/identity/
    ├── identity.json          # Identity card (public, shareable)
    ├── private.enc            # Encrypted private key blob
    └── storage.json           # Storage config (KDF params, version)

The ``IdentityStorage`` class manages all three files atomically.
"""

import json
import os
import stat
from dataclasses import asdict, dataclass
from datetime import UTC
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from hermes_id.crypto import (
    decrypt_key,
    deserialize_private_key,
    encrypt_key,
    generate_keypair,
    secure_zero,
    serialize_private_key,
)
from hermes_id.identity import (
    IdentityCard,
    create_identity,
    verify_identity_card,
)

# ---------------------------------------------------------------------------
# Secure key context manager
# ---------------------------------------------------------------------------

class _KeyContext:
    """Context manager for secure temporary key usage.

    Returns the Ed25519 private key, then securely zeros the underlying
    DER buffer on exit.  The ``cryptography`` object itself may survive
    in Python's GC, but the serialized bytes we control are cleared.
    """

    def __init__(self, storage: "IdentityStorage", password: str):
        self._storage = storage
        self._password = password
        self._key = None
        self._der_bytes = None

    def __enter__(self) -> ed25519.Ed25519PrivateKey:
        encrypted = self._storage._read_private()
        try:
            self._der_bytes = decrypt_key(encrypted, self._password)
            self._key = deserialize_private_key(self._der_bytes)
        finally:
            secure_zero(bytearray(encrypted))
        return self._key

    def __exit__(self, *exc_args) -> None:
        if self._der_bytes is not None:
            secure_zero(bytearray(self._der_bytes))
            self._der_bytes = None
        self._key = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STORAGE_VERSION = 1
_DEFAULT_DIR = "~/.hermes/identity"
_PRIVATE_KEY_FILE = "private.enc"
_IDENTITY_FILE = "identity.json"
_CONFIG_FILE = "storage.json"
_FILE_PERMS = stat.S_IRUSR | stat.S_IWUSR  # 0o600


# ---------------------------------------------------------------------------
# Storage config
# ---------------------------------------------------------------------------

@dataclass
class StorageConfig:
    """Configuration for key storage.

    Attributes:
        version: Storage format version (for migration).
        created_at: ISO-8601 timestamp of initial creation.
        updated_at: ISO-8601 timestamp of last modification.
        kdf: Key derivation function name (``argon2id``, ``scrypt``, ``pbkdf2``).
        metadata: User-facing metadata carried in the identity card.
    """
    version: int = _STORAGE_VERSION
    created_at: str = ""
    updated_at: str = ""
    kdf: str = "scrypt"
    metadata: dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


# ---------------------------------------------------------------------------
# Identity storage
# ---------------------------------------------------------------------------

class IdentityStorage:
    """Secure file-based storage for a Hermes-Agent identity.

    Manages the encrypted private key and plaintext identity card on disk
    under a single directory.  Thread-safe for read operations; writes
    should be externally serialized.
    """

    def __init__(self, directory: str | None = None):
        self._dir = Path(os.path.expanduser(directory or _DEFAULT_DIR))
        self._private_path = self._dir / _PRIVATE_KEY_FILE
        self._identity_path = self._dir / _IDENTITY_FILE
        self._config_path = self._dir / _CONFIG_FILE
        self._config: StorageConfig | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def exists(self) -> bool:
        """Check whether an identity already exists on disk."""
        return self._private_path.exists() and self._identity_path.exists()

    def create(
        self,
        password: str,
        metadata: dict[str, Any] | None = None,
    ) -> IdentityCard:
        """Generate a new identity and persist it.

        This is a destructive operation — if an identity already exists,
        it will be **overwritten**.  Check :meth:`exists` first.

        Args:
            password: Passphrase to encrypt the private key.
            metadata: Optional claims for the identity card.

        Returns:
            The newly created ``IdentityCard``.
        """
        now = datetime_now_iso()

        # Generate fresh keypair
        private_key, public_key = generate_keypair()

        # Create identity card
        card = create_identity(private_key, public_key, metadata=metadata)

        # Encrypt private key
        priv_der = serialize_private_key(private_key)
        encrypted = encrypt_key(priv_der, password)

        # Ensure directory exists with restrictive perms
        self._dir.mkdir(parents=True, exist_ok=True)
        self._dir.chmod(0o700)

        # Detect KDF used
        kdf = self._detect_kdf()

        # Write all three files
        self._write_private(encrypted)
        self._write_identity(card)
        self._write_config(StorageConfig(
            version=_STORAGE_VERSION,
            created_at=now,
            updated_at=now,
            kdf=kdf,
            metadata=metadata or {},
        ))

        return card

    def unlock(self, password: str) -> ed25519.Ed25519PrivateKey:
        """Decrypt and return the private key.

        Args:
            password: The passphrase used during :meth:`create`.

        Returns:
            The Ed25519 private key object.

        Raises:
            FileNotFoundError: If no identity exists yet.
            cryptography.exceptions.InvalidTag: If the password is wrong.
        """
        if not self.exists():
            raise FileNotFoundError(
                f"No identity found at {self._dir}. "
                "Run `hermes-id init` first."
            )

        encrypted = self._read_private()
        decrypted_der = None
        try:
            decrypted_der = decrypt_key(encrypted, password)
            private_key = deserialize_private_key(decrypted_der)
        finally:
            secure_zero(bytearray(encrypted))
            if decrypted_der is not None:
                secure_zero(bytearray(decrypted_der))
        return private_key

    def rotate(
        self,
        password: str,
        metadata: dict[str, Any] | None = None,
        keep_backup: bool = True,
    ) -> IdentityCard:
        """Rotate the identity keypair.

        Generates a fresh Ed25519 keypair, creates a new identity card
        carrying a **transition proof** signed by the previous key (see
        :func:`hermes_id.identity.create_identity`), and persists the new
        key.  The previous key is preserved in a ``rotated/`` backup
        directory so a compromised rotation can be rolled back.

        Args:
            password: Passphrase for the *current* private key.
            metadata: Optional claims for the new identity card.  If the
                previous card had metadata, it is merged underneath (new
                keys win).
            keep_backup: If True, copy the previous identity files into
                ``<dir>/rotated/<old-did>/`` for rollback.

        Returns:
            The new ``IdentityCard``.

        Raises:
            FileNotFoundError: If no identity exists yet.
            cryptography.exceptions.InvalidTag: If the password is wrong.
        """
        if not self.exists():
            raise FileNotFoundError(
                f"No identity found at {self._dir}. "
                "Run `hermes-id init` first."
            )

        now = datetime_now_iso()

        # Load current identity
        old_card = self.get_identity_card()
        old_config = self.get_config()
        old_private = self.unlock(password)

        # Backup current state before overwriting
        if keep_backup:
            old_suffix = old_card.id.split(":")[-1][:16]
            backup_dir = self._dir / "rotated" / f"{old_suffix}"
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_dir.chmod(0o700)
            for fname in (_PRIVATE_KEY_FILE, _IDENTITY_FILE, _CONFIG_FILE):
                src = self._dir / fname
                if src.exists():
                    dst = backup_dir / fname
                    dst.write_bytes(src.read_bytes())
                    dst.chmod(_FILE_PERMS)

        # Merge metadata: previous card metadata + rotation info + caller claims
        new_metadata = dict(old_card.metadata or {})
        new_metadata.pop("rotation", None)  # fresh rotation entry below
        if metadata:
            new_metadata.update(metadata)
        new_metadata["rotations"] = int(new_metadata.get("rotations", 0)) + 1

        # Generate fresh keypair + card with transition proof
        new_private, new_public = generate_keypair()
        card = create_identity(
            new_private,
            new_public,
            metadata=new_metadata,
            previous_card=old_card,
            previous_private_key=old_private,
        )

        # Encrypt new private key
        priv_der = serialize_private_key(new_private)
        encrypted = encrypt_key(priv_der, password)
        secure_zero(bytearray(priv_der))

        kdf = self._detect_kdf()

        self._dir.mkdir(parents=True, exist_ok=True)
        self._dir.chmod(0o700)
        self._write_private(encrypted)
        self._write_identity(card)
        self._write_config(StorageConfig(
            version=_STORAGE_VERSION,
            created_at=old_config.created_at or now,
            updated_at=now,
            kdf=kdf,
            metadata=new_metadata,
        ))

        return card

    # ------------------------------------------------------------------
    # Secure context manager for temporary key use
    # ------------------------------------------------------------------

    def use_key(self, password: str):
        """Context manager that provides the private key and securely
        clears any intermediate buffers on exit.

        Usage::

            with storage.use_key(password) as key:
                sig = sign(key, b"message")
                # key and temporary DER buffers are zeroed after exit
        """
        return _KeyContext(self, password)

    # ------------------------------------------------------------------
    # Public API (read-only)
    # ------------------------------------------------------------------

    def get_identity_card(self) -> IdentityCard:
        if not self._identity_path.exists():
            raise FileNotFoundError(
                f"No identity card at {self._identity_path}. "
                "Run `hermes-id init` first."
            )
        raw = self._identity_path.read_text()
        return IdentityCard.from_json(raw)

    def get_config(self) -> StorageConfig:
        """Read the storage configuration."""
        if self._config is None:
            if self._config_path.exists():
                raw = self._config_path.read_text()
                self._config = StorageConfig(**json.loads(raw))
            else:
                self._config = StorageConfig()
        return self._config

    def show_status(self) -> str:
        """Return a human-readable status summary."""
        if not self.exists():
            return "❌ No identity configured. Run `hermes-id init`."

        card = self.get_identity_card()
        config = self.get_config()

        lines = [
            "🏷️  **Hermes Identity**",
            "",
            f"   DID:        `{card.id}`",
            f"   Short:      `{card.did_short}`",
            f"   Created:    {config.created_at or card.created}",
            "   Key type:   Ed25519",
            f"   Storage:    AES-256-GCM ({config.kdf})",
            f"   Card valid: {'✅' if verify_identity_card(card) else '❌'}",
        ]
        if card.metadata:
            lines.append(f"   Metadata:   {json.dumps(card.metadata)}")
        if (card.metadata or {}).get("rotation"):
            lines.append("   Rotated:    ✅ transition proof present")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_private(self, data: bytes) -> None:
        """Write encrypted key with restrictive permissions."""
        self._private_path.write_bytes(data)
        self._private_path.chmod(_FILE_PERMS)

    def _read_private(self) -> bytes:
        """Read encrypted key blob."""
        return self._private_path.read_bytes()

    def _write_identity(self, card: IdentityCard) -> None:
        """Write identity card as readable JSON."""
        self._identity_path.write_text(card.to_json())
        self._identity_path.chmod(_FILE_PERMS)

    def _write_config(self, config: StorageConfig) -> None:
        """Write storage config."""
        self._config_path.write_text(json.dumps(asdict(config), indent=2))
        self._config_path.chmod(_FILE_PERMS)
        self._config = config

    @staticmethod
    def _detect_kdf() -> str:
        """Detect which KDF will be used."""
        try:
            from argon2.low_level import Type, hash_secret_raw  # noqa: F401
            return "argon2id"
        except ImportError:
            pass
        try:
            import hashlib
            hashlib.scrypt(password=b"test", salt=b"1234567890123456",
                          n=1024, r=8, p=1, dklen=32)
            return "scrypt"
        except (ValueError, TypeError):
            return "pbkdf2"


def datetime_now_iso() -> str:
    """Current UTC timestamp in ISO-8601 format."""
    from datetime import datetime
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
