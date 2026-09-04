"""Tests for GF(256) Shamir secret sharing."""

from __future__ import annotations

import secrets

import pytest

from cryptolab_suite.shamir import Share, combine, split


def test_roundtrip_basic() -> None:
    secret = b"hello-shamir-secret-bytes!!"
    shares = split(secret, n=5, k=3)
    assert len(shares) == 5
    recovered = combine(shares[:3])
    assert recovered == secret
    recovered2 = combine([shares[0], shares[2], shares[4]])
    assert recovered2 == secret


def test_too_few_shares_wrong() -> None:
    secret = b"abcdefgh"
    shares = split(secret, n=5, k=3)
    # With only 2 shares of a k=3 scheme, reconstruction is wrong (almost surely).
    wrong = combine(shares[:2])
    assert wrong != secret


def test_share_hex_codec() -> None:
    s = Share(x=7, y=b"\x01\x02\xff")
    parsed = Share.from_hex(s.to_hex())
    assert parsed == s


def test_invalid_params() -> None:
    with pytest.raises(ValueError):
        split(b"x", n=2, k=3)
    with pytest.raises(ValueError):
        split(b"", n=3, k=2)


def test_deterministic_with_rng() -> None:
    class Fake:
        def __init__(self) -> None:
            self.i = 0

        def randrange(self, a: int, b: int) -> int:
            self.i = (self.i + 17) % (b - a)
            return a + self.i

    secret = b"ABC"
    rng = Fake()
    s1 = split(secret, 3, 2, rng=rng)  # type: ignore[arg-type]
    rng2 = Fake()
    s2 = split(secret, 3, 2, rng=rng2)  # type: ignore[arg-type]
    assert [x.to_hex() for x in s1] == [x.to_hex() for x in s2]
    assert combine(s1[:2]) == secret
