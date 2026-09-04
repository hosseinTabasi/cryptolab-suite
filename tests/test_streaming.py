"""Tests for chunked AES-GCM streaming."""

from __future__ import annotations

from pathlib import Path

import pytest

from cryptolab_suite.streaming import decrypt_stream, encrypt_stream, generate_key


def test_stream_roundtrip(tmp_path: Path) -> None:
    src = tmp_path / "plain.bin"
    enc = tmp_path / "out.strm"
    dec = tmp_path / "dec.bin"
    data = b"A" * 200_000 + b"tail"
    src.write_bytes(data)
    key = generate_key()
    encrypt_stream(src, enc, key, associated_data=b"meta", chunk_size=4096)
    decrypt_stream(enc, dec, key, associated_data=b"meta")
    assert dec.read_bytes() == data


def test_aad_mismatch(tmp_path: Path) -> None:
    src = tmp_path / "plain.bin"
    enc = tmp_path / "out.strm"
    dec = tmp_path / "dec.bin"
    src.write_bytes(b"hello world")
    key = generate_key()
    encrypt_stream(src, enc, key, associated_data=b"one")
    with pytest.raises(ValueError):
        decrypt_stream(enc, dec, key, associated_data=b"two")


def test_empty_file(tmp_path: Path) -> None:
    src = tmp_path / "empty"
    enc = tmp_path / "out.strm"
    dec = tmp_path / "dec"
    src.write_bytes(b"")
    key = generate_key()
    encrypt_stream(src, enc, key)
    decrypt_stream(enc, dec, key)
    assert dec.read_bytes() == b""
