"""cryptolab-suite: advanced cryptography lab extending cryptolab-kit.

New modules cover Shamir secret sharing, Merkle trees, an X.509 toolkit,
a local encrypted vault, streaming AES-GCM, a toy handshake demo,
benchmarks, and an offline challenge lab.

Educational modules are labelled **EDUCATIONAL** and must never protect
real secrets. Safe modules use ``cryptography`` / ``argon2-cffi`` and
still require careful key handling. See ``docs/SECURITY.md``.
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "Hossein Tabasi"

__all__ = [
    "__author__",
    "__version__",
]
