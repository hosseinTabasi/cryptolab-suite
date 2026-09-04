"""Live micro-benchmarks for educational vs library crypto.

**EDUCATIONAL timing** for textbook RSA; **SAFE** timing for
cryptography RSA-OAEP and AES-GCM. Numbers are measured at runtime —
never invented.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class BenchRow:
    """One benchmark result row."""

    name: str
    label: str  # EDUCATIONAL | SAFE
    iterations: int
    total_seconds: float
    extra: str = ""

    @property
    def per_op_ms(self) -> float:
        """Milliseconds per operation."""
        if self.iterations <= 0:
            return float("inf")
        return (self.total_seconds / self.iterations) * 1000.0

    @property
    def throughput_mib_s(self) -> float | None:
        """MiB/s if ``extra`` encodes buffer size as ``buf=N``."""
        if not self.extra.startswith("buf="):
            return None
        nbytes = int(self.extra.split("=", 1)[1])
        if self.total_seconds <= 0:
            return None
        return (nbytes * self.iterations) / self.total_seconds / (1024 * 1024)


def _time_loop(fn, iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    return time.perf_counter() - start


def bench_textbook_rsa(iterations: int = 500) -> BenchRow:
    """Time educational tiny textbook RSA encrypt+decrypt of a small int."""
    try:
        from cryptolab.rsa_edu.textbook_rsa import (
            DEMO_E,
            DEMO_P,
            DEMO_Q,
            rsa_decrypt,
            rsa_encrypt,
            rsa_keygen,
        )
    except ImportError:
        # Fallback identical tiny RSA without kit (same demo primes).
        from cryptolab_suite.kit_bridge import KitNotInstalledError

        raise KitNotInstalledError(
            "bench textbook RSA needs cryptolab-kit (rsa_edu). "
            "pip install -e ../cryptolab-kit"
        ) from None

    key = rsa_keygen(DEMO_P, DEMO_Q, DEMO_E)
    message = 65

    def once() -> None:
        c = rsa_encrypt(message, key.public_key)
        m = rsa_decrypt(c, key)
        if m != message:
            raise RuntimeError("textbook RSA round-trip failed")

    elapsed = _time_loop(once, iterations)
    return BenchRow(
        name="textbook RSA enc+dec (tiny n=3233)",
        label="EDUCATIONAL",
        iterations=iterations,
        total_seconds=elapsed,
    )


def bench_rsa_oaep_wrap(iterations: int = 50) -> BenchRow:
    """Time cryptography RSA-OAEP wrap/unwrap of a 32-byte key (2048-bit)."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    secret = os.urandom(32)

    def once() -> None:
        ct = public.encrypt(secret, oaep)
        pt = private.decrypt(ct, oaep)
        if pt != secret:
            raise RuntimeError("OAEP round-trip failed")

    elapsed = _time_loop(once, iterations)
    return BenchRow(
        name="RSA-OAEP wrap 32-byte key (2048-bit)",
        label="SAFE",
        iterations=iterations,
        total_seconds=elapsed,
    )


def bench_aes_gcm(buffer_size: int, iterations: int = 100) -> BenchRow:
    """Time AES-256-GCM encrypt+decrypt on an in-memory buffer."""
    key = os.urandom(32)
    aead = AESGCM(key)
    plain = os.urandom(buffer_size)

    def once() -> None:
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, plain, None)
        out = aead.decrypt(nonce, ct, None)
        if out != plain:
            raise RuntimeError("AES-GCM round-trip failed")

    elapsed = _time_loop(once, iterations)
    return BenchRow(
        name=f"AES-256-GCM enc+dec ({buffer_size // (1024 * 1024)} MiB)",
        label="SAFE",
        iterations=iterations,
        total_seconds=elapsed,
        extra=f"buf={buffer_size}",
    )


def run_all() -> list[BenchRow]:
    """Run the standard suite of live benchmarks."""
    rows: list[BenchRow] = []
    rows.append(bench_textbook_rsa())
    rows.append(bench_rsa_oaep_wrap())
    for mib in (1, 2, 4):
        rows.append(bench_aes_gcm(mib * 1024 * 1024, iterations=40))
    return rows


def format_table(rows: list[BenchRow]) -> str:
    """Pretty-print a results table."""
    headers = ("Name", "Label", "Iters", "Total s", "ms/op", "MiB/s")
    table_rows: list[tuple[str, ...]] = [headers]
    for r in rows:
        thr = r.throughput_mib_s
        thr_s = f"{thr:.2f}" if thr is not None else "—"
        table_rows.append(
            (
                r.name,
                r.label,
                str(r.iterations),
                f"{r.total_seconds:.4f}",
                f"{r.per_op_ms:.3f}",
                thr_s,
            )
        )
    widths = [max(len(row[i]) for row in table_rows) for i in range(len(headers))]
    lines = [
        "cryptolab-suite benchmarks (live measurements)",
        "EDUCATIONAL rows are textbook demos; SAFE rows use cryptography.",
        "",
    ]
    sep = "  ".join("-" * w for w in widths)
    for i, row in enumerate(table_rows):
        line = "  ".join(cell.ljust(widths[j]) for j, cell in enumerate(row))
        lines.append(line)
        if i == 0:
            lines.append(sep)
    return "\n".join(lines) + "\n"
