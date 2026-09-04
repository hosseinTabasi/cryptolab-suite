"""Chunked streaming AES-256-GCM for large files.

**SAFE:** encrypts/decrypts files in framed chunks so payloads larger
than a single in-memory buffer are practical. Each chunk has its own
nonce; AAD binds the stream header and chunk index.

File format::

    magic (8)  = b'CLSTRM01'
    key_id hint unused (0)
    aad_len (2 BE) + aad bytes
    chunk_size (4 BE)   # plaintext chunk size used on encrypt
    then repeated frames:
        chunk_index (4 BE)
        nonce (12)
        ct_len (4 BE)
        ciphertext||tag
    final frame: chunk_index with high bit set (EOF marker), ct_len=0

Reuse patterns from cryptolab-kit one-shot AES-GCM where sensible
(AESGCM, 12-byte nonce, 32-byte key) but framing is suite-specific.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CLSTRM01"
NONCE_SIZE = 12
KEY_SIZE = 32
DEFAULT_CHUNK = 64 * 1024  # 64 KiB plaintext per chunk
EOF_FLAG = 0x80000000


def generate_key() -> bytes:
    """Return a fresh 32-byte AES-256 key."""
    return os.urandom(KEY_SIZE)


def _require_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")


def encrypt_stream(
    src: str | Path,
    dest: str | Path,
    key: bytes,
    *,
    associated_data: bytes = b"",
    chunk_size: int = DEFAULT_CHUNK,
) -> Path:
    """Encrypt ``src`` to framed ``dest`` with AES-256-GCM chunks."""
    _require_key(key)
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    src_path = Path(src)
    dest_path = Path(dest)
    aead = AESGCM(key)
    aad = associated_data

    with src_path.open("rb") as fin, dest_path.open("wb") as fout:
        fout.write(MAGIC)
        fout.write(struct.pack(">H", len(aad)))
        fout.write(aad)
        fout.write(struct.pack(">I", chunk_size))
        index = 0
        while True:
            plain = fin.read(chunk_size)
            if not plain:
                # EOF marker frame
                fout.write(struct.pack(">I", EOF_FLAG | index))
                fout.write(b"\x00" * NONCE_SIZE)
                fout.write(struct.pack(">I", 0))
                break
            nonce = os.urandom(NONCE_SIZE)
            # Bind header AAD + chunk index into per-chunk AAD.
            chunk_aad = aad + struct.pack(">I", index)
            ct = aead.encrypt(nonce, plain, chunk_aad)
            fout.write(struct.pack(">I", index))
            fout.write(nonce)
            fout.write(struct.pack(">I", len(ct)))
            fout.write(ct)
            index += 1
    return dest_path


def decrypt_stream(
    src: str | Path,
    dest: str | Path,
    key: bytes,
    *,
    associated_data: bytes | None = None,
) -> Path:
    """Decrypt a framed stream produced by :func:`encrypt_stream`."""
    _require_key(key)
    src_path = Path(src)
    dest_path = Path(dest)
    aead = AESGCM(key)

    with src_path.open("rb") as fin, dest_path.open("wb") as fout:
        magic = fin.read(8)
        if magic != MAGIC:
            raise ValueError("not a cryptolab-suite stream (bad magic)")
        (aad_len,) = struct.unpack(">H", fin.read(2))
        file_aad = fin.read(aad_len)
        if associated_data is not None and associated_data != file_aad:
            raise ValueError("associated_data mismatch")
        aad = file_aad if associated_data is None else associated_data
        fin.read(4)  # chunk_size — informational
        expected = 0
        while True:
            hdr = fin.read(4)
            if len(hdr) < 4:
                raise ValueError("truncated stream (missing EOF)")
            (raw_index,) = struct.unpack(">I", hdr)
            nonce = fin.read(NONCE_SIZE)
            (ct_len,) = struct.unpack(">I", fin.read(4))
            if raw_index & EOF_FLAG:
                if ct_len != 0:
                    raise ValueError("corrupt EOF frame")
                break
            if raw_index != expected:
                raise ValueError(f"chunk index mismatch: got {raw_index}, want {expected}")
            ct = fin.read(ct_len)
            if len(ct) != ct_len:
                raise ValueError("truncated chunk")
            chunk_aad = aad + struct.pack(">I", raw_index)
            plain = aead.decrypt(nonce, ct, chunk_aad)
            fout.write(plain)
            expected += 1
    return dest_path
