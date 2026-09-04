"""Shamir's Secret Sharing over GF(256).

**EDUCATIONAL — not for production key custody without independent audit.**

This implementation uses the AES field GF(2^8) with the irreducible
polynomial ``x^8 + x^4 + x^3 + x + 1`` (0x11b), the same field as AES.
Each secret byte is shared independently with a degree-(k-1) polynomial;
share *i* stores the evaluations at x = i (1..n).

Field choice: **GF(256)** (byte-oriented). Documented here and in
``docs/ARCHITECTURE.md``. A prime-field variant is not provided.

References: Shamir, *How to Share a Secret* (CACM 1979); AES field
arithmetic (FIPS 197).
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass


# AES irreducible polynomial for GF(2^8).
_AES_POLY = 0x11B


def _gf_mul(a: int, b: int) -> int:
    """Multiply two GF(256) elements."""
    a &= 0xFF
    b &= 0xFF
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= _AES_POLY & 0xFF
        b >>= 1
    return p


def _gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(256) via Fermat: a^(254)."""
    if a == 0:
        raise ZeroDivisionError("no inverse for 0 in GF(256)")
    # a^254 = a^(2^8 - 2)
    result = 1
    base = a & 0xFF
    exp = 254
    while exp:
        if exp & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return result


def _poly_eval(coeffs: list[int], x: int) -> int:
    """Evaluate polynomial with GF(256) coeffs at ``x`` (Horner)."""
    y = 0
    for c in reversed(coeffs):
        y = _gf_mul(y, x) ^ (c & 0xFF)
    return y


def _lagrange_at_zero(xs: list[int], ys: list[int]) -> int:
    """Interpolate y-values at xs and evaluate the polynomial at 0."""
    secret = 0
    k = len(xs)
    for i in range(k):
        numer = 1
        denom = 1
        for j in range(k):
            if i == j:
                continue
            numer = _gf_mul(numer, xs[j])
            denom = _gf_mul(denom, xs[j] ^ xs[i])
        li0 = _gf_mul(numer, _gf_inv(denom))
        secret ^= _gf_mul(ys[i], li0)
    return secret


@dataclass(frozen=True)
class Share:
    """One Shamir share: index ``x`` in 1..255 and share bytes ``y``.

    **EDUCATIONAL.**
    """

    x: int
    y: bytes

    def to_hex(self) -> str:
        """Encode as ``x-hex(y)`` for CLI / file storage."""
        return f"{self.x:02x}-{self.y.hex()}"

    @classmethod
    def from_hex(cls, text: str) -> Share:
        """Parse ``x-hex(y)`` produced by :meth:`to_hex`."""
        text = text.strip()
        if "-" not in text:
            raise ValueError("share format must be '<xhex>-<yhex>'")
        x_hex, y_hex = text.split("-", 1)
        x = int(x_hex, 16)
        if not (1 <= x <= 255):
            raise ValueError("share index x must be in 1..255")
        y = bytes.fromhex(y_hex)
        return cls(x=x, y=y)


def split(secret: bytes, n: int, k: int, *, rng: secrets.SystemRandom | None = None) -> list[Share]:
    """Split ``secret`` into ``n`` shares with threshold ``k``.

    Parameters
    ----------
    secret:
        Arbitrary-length secret bytes.
    n:
        Total number of shares (1 <= n <= 255).
    k:
        Reconstruction threshold (1 <= k <= n).
    rng:
        Optional CSPRNG (tests may inject a deterministic source).

    Returns
    -------
    list[Share]
        ``n`` shares. Any ``k`` of them reconstruct ``secret``.

    **EDUCATIONAL — not for production key custody without audit.**
    """
    if not (1 <= k <= n <= 255):
        raise ValueError("require 1 <= k <= n <= 255")
    if not secret:
        raise ValueError("secret must be non-empty")

    rand = rng if rng is not None else secrets.SystemRandom()
    shares_y: list[bytearray] = [bytearray() for _ in range(n)]
    xs = list(range(1, n + 1))

    for byte in secret:
        coeffs = [byte & 0xFF]
        for _ in range(k - 1):
            coeffs.append(rand.randrange(0, 256))
        for i, x in enumerate(xs):
            shares_y[i].append(_poly_eval(coeffs, x))

    return [Share(x=xs[i], y=bytes(shares_y[i])) for i in range(n)]


def combine(shares: list[Share]) -> bytes:
    """Reconstruct the secret from at least ``k`` shares.

    Shares must have distinct ``x`` values and equal-length ``y``.

    **EDUCATIONAL — not for production key custody without audit.**
    """
    if not shares:
        raise ValueError("need at least one share")
    length = len(shares[0].y)
    if length == 0:
        raise ValueError("share payload empty")
    xs: list[int] = []
    seen: set[int] = set()
    for s in shares:
        if s.x in seen:
            raise ValueError(f"duplicate share index {s.x}")
        if not (1 <= s.x <= 255):
            raise ValueError("share index x must be in 1..255")
        if len(s.y) != length:
            raise ValueError("all shares must have equal length")
        seen.add(s.x)
        xs.append(s.x)

    out = bytearray()
    for i in range(length):
        ys = [s.y[i] for s in shares]
        out.append(_lagrange_at_zero(xs, ys))
    return bytes(out)


def split_to_files(
    secret: bytes,
    n: int,
    k: int,
    out_dir: str | os.PathLike[str],
) -> list[str]:
    """Split and write share files ``share-01.txt`` … under ``out_dir``."""
    from pathlib import Path

    path = Path(out_dir)
    path.mkdir(parents=True, exist_ok=True)
    shares = split(secret, n, k)
    written: list[str] = []
    for s in shares:
        dest = path / f"share-{s.x:02d}.txt"
        dest.write_text(s.to_hex() + "\n", encoding="utf-8")
        written.append(str(dest))
    return written


def combine_from_files(paths: list[str | os.PathLike[str]]) -> bytes:
    """Load share files and combine."""
    from pathlib import Path

    shares = [Share.from_hex(Path(p).read_text(encoding="utf-8")) for p in paths]
    return combine(shares)
