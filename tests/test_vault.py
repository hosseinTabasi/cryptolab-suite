"""Tests for Argon2id + AES-GCM vault."""

from __future__ import annotations

from pathlib import Path

import pytest

from cryptolab_suite.vault import init_vault, unlock_vault


def test_vault_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "lab.vault"
    v = init_vault(path, "correct horse battery")
    v.set("api", "token-123")
    v.set("db", "s3cret")
    assert v.list_names() == ["api", "db"]

    v2 = unlock_vault(path, "correct horse battery")
    assert v2.get("api") == "token-123"
    assert v2.get("db") == "s3cret"

    exported = v2.export_encrypted(tmp_path / "copy.vault")
    v3 = unlock_vault(exported, "correct horse battery")
    assert v3.get("api") == "token-123"


def test_wrong_passphrase(tmp_path: Path) -> None:
    path = tmp_path / "lab.vault"
    init_vault(path, "good-pass")
    with pytest.raises(ValueError):
        unlock_vault(path, "bad-pass")


def test_exists(tmp_path: Path) -> None:
    path = tmp_path / "lab.vault"
    init_vault(path, "pw")
    with pytest.raises(FileExistsError):
        init_vault(path, "pw")
