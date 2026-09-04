"""Tests for offline challenge lab."""

from __future__ import annotations

from cryptolab_suite.challenges import (
    caesar_decrypt_local,
    check_answer,
    get_challenge,
    list_challenges,
    vigenere_decrypt_local,
)


def test_list_nonempty() -> None:
    assert len(list_challenges()) >= 3


def test_chal_01() -> None:
    c = get_challenge("chal-01")
    plain = caesar_decrypt_local(c.ciphertext, 7)
    assert check_answer("chal-01", plain)
    assert not check_answer("chal-01", "WRONG")


def test_chal_02() -> None:
    c = get_challenge("chal-02")
    plain = vigenere_decrypt_local(c.ciphertext, "LEMON")
    assert check_answer("chal-02", plain)


def test_chal_03() -> None:
    c = get_challenge("chal-03")
    plain = caesar_decrypt_local(c.ciphertext, 4)
    assert check_answer("chal-03", plain)
