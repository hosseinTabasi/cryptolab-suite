"""Tests for educational toy handshake."""

from __future__ import annotations

from cryptolab_suite.handshake import run_honest_handshake, run_mitm_simulation


def test_honest_succeeds() -> None:
    result = run_honest_handshake()
    assert result.success
    assert result.alice_ok and result.bob_ok
    assert not result.mitm


def test_mitm_fails() -> None:
    result = run_mitm_simulation()
    assert not result.success
    assert not result.alice_ok
    assert not result.bob_ok
    assert result.mitm
