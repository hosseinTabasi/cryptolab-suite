"""Tests for X.509 toolkit."""

from __future__ import annotations

from pathlib import Path

from cryptolab_suite.x509_tools import generate_ca, inspect_cert, issue_leaf, write_bundle


def test_ca_and_leaf(tmp_path: Path) -> None:
    ca = generate_ca("Test CA", key_type="ec")
    info = inspect_cert(ca.cert_pem)
    assert info["is_ca"] is True
    assert "Test CA" in str(info["subject"])

    leaf = issue_leaf(
        ca.cert_pem,
        ca.key_pem,
        "app.example.test",
        sans=["app.example.test", "localhost"],
        key_type="rsa",
    )
    leaf_info = inspect_cert(leaf.cert_pem)
    assert leaf_info["is_ca"] is False
    assert "app.example.test" in leaf_info["san_dns"]
    assert "localhost" in leaf_info["san_dns"]

    write_bundle(ca, tmp_path / "ca.crt", tmp_path / "ca.key")
    assert (tmp_path / "ca.crt").read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
