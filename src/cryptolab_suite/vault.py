"""Local encrypted secrets vault.

**SAFE:** Argon2id passphrase KDF → AES-256-GCM encrypted JSON store of
named secrets. Only salt + ciphertext are written to disk. Passphrases
are never logged or stored.

On-disk format (binary)::

    magic (6) = b'CLVLT1'
    salt_len (1) + salt
    nonce (12) + ciphertext||tag   # AES-GCM over UTF-8 JSON payload

JSON payload::

    {"version": 1, "secrets": {"name": "value", ...}}
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CLVLT1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
# Argon2id parameters — reasonable lab defaults (tunable).
ARGON2_TIME = 3
ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 2


@dataclass
class Vault:
    """In-memory vault after unlock."""

    path: Path
    secrets: dict[str, str]
    _key: bytes
    _salt: bytes

    def list_names(self) -> list[str]:
        """Return sorted secret names."""
        return sorted(self.secrets)

    def get(self, name: str) -> str:
        """Return a secret value by name."""
        if name not in self.secrets:
            raise KeyError(f"secret not found: {name}")
        return self.secrets[name]

    def set(self, name: str, value: str) -> None:
        """Set or overwrite a named secret and persist."""
        if not name or not isinstance(name, str):
            raise ValueError("name must be a non-empty string")
        self.secrets[name] = value
        self._persist()

    def delete(self, name: str) -> None:
        """Remove a secret and persist."""
        if name not in self.secrets:
            raise KeyError(f"secret not found: {name}")
        del self.secrets[name]
        self._persist()

    def export_encrypted(self, dest: str | Path) -> Path:
        """Copy the on-disk encrypted blob to ``dest`` (already encrypted)."""
        dest_path = Path(dest)
        dest_path.write_bytes(self.path.read_bytes())
        return dest_path

    def _persist(self) -> None:
        payload = json.dumps(
            {"version": 1, "secrets": self.secrets},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        nonce = os.urandom(NONCE_SIZE)
        ct = AESGCM(self._key).encrypt(nonce, payload, MAGIC)
        blob = MAGIC + bytes([len(self._salt)]) + self._salt + nonce + ct
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(blob)


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise ValueError("passphrase must be non-empty")
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def init_vault(path: str | Path, passphrase: str) -> Vault:
    """Create a new empty vault at ``path``.

    Raises
    ------
    FileExistsError
        If the path already exists.
    """
    dest = Path(path)
    if dest.exists():
        raise FileExistsError(f"vault already exists: {dest}")
    salt = os.urandom(SALT_SIZE)
    key = _derive_key(passphrase, salt)
    vault = Vault(path=dest, secrets={}, _key=key, _salt=salt)
    vault._persist()
    return vault


def unlock_vault(path: str | Path, passphrase: str) -> Vault:
    """Unlock an existing vault with ``passphrase``."""
    dest = Path(path)
    blob = dest.read_bytes()
    if not blob.startswith(MAGIC):
        raise ValueError("not a cryptolab-suite vault (bad magic)")
    salt_len = blob[len(MAGIC)]
    off = len(MAGIC) + 1
    salt = blob[off : off + salt_len]
    off += salt_len
    if len(salt) != salt_len or len(blob) < off + NONCE_SIZE + 16:
        raise ValueError("truncated vault file")
    nonce = blob[off : off + NONCE_SIZE]
    ct = blob[off + NONCE_SIZE :]
    key = _derive_key(passphrase, salt)
    try:
        plain = AESGCM(key).decrypt(nonce, ct, MAGIC)
    except Exception as exc:  # InvalidTag etc.
        raise ValueError("wrong passphrase or corrupted vault") from exc
    data = json.loads(plain.decode("utf-8"))
    if not isinstance(data, dict) or "secrets" not in data:
        raise ValueError("invalid vault payload")
    secrets = {str(k): str(v) for k, v in data["secrets"].items()}
    return Vault(path=dest, secrets=secrets, _key=key, _salt=salt)
