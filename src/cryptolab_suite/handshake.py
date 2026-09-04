"""Toy mutual handshake: X25519 ephemeral ECDH + HKDF + AES-GCM Finished.

**EDUCATIONAL.** Offline simulation of two honest parties (and an optional
active adversary that fails transcript verification). This is **not**
TLS, **not** Noise, and **not** network attack tooling — all messages
are exchanged in-process.

Protocol sketch
---------------
1. Alice and Bob generate ephemeral X25519 key pairs.
2. They exchange public keys and build a transcript hash
   ``H = SHA256(AlicePub || BobPub)``.
3. Shared secret ``ss = X25519(sk, peer_pk)``.
4. ``key = HKDF-SHA256(ss, info=b"cryptolab-suite-hs", length=32)``.
5. Each side sends ``Finished = AESGCM(key).encrypt(nonce, b"finished", H)``.
6. Peer verifies decrypt under the same key and AAD=H.

MITM demo: an adversary replaces public keys; honest parties derive
different keys / transcripts and Finished verification fails.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"cryptolab-suite-hs-v1"
FINISHED_PLAIN = b"finished"


@dataclass
class Party:
    """One handshake participant."""

    name: str
    private: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate)
    peer_public: bytes | None = None
    session_key: bytes | None = None
    transcript: bytes | None = None

    @property
    def public_bytes(self) -> bytes:
        """Raw 32-byte X25519 public key."""
        return self.private.public_key().public_bytes_raw()

    def receive_peer(self, peer_pub: bytes) -> None:
        """Record peer public key (raw 32 bytes)."""
        if len(peer_pub) != 32:
            raise ValueError("X25519 public key must be 32 bytes")
        self.peer_public = peer_pub

    def derive(self, *, alice_pub: bytes, bob_pub: bytes) -> None:
        """Derive session key and transcript from ordered public keys."""
        if self.peer_public is None:
            raise RuntimeError("peer public key not set")
        shared = self.private.exchange(X25519PublicKey.from_public_bytes(self.peer_public))
        self.transcript = sha256(alice_pub + bob_pub).digest()
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=INFO,
        ).derive(shared)

    def finished_message(self) -> bytes:
        """Produce AES-GCM Finished blob: nonce||ct||tag with AAD=transcript."""
        if self.session_key is None or self.transcript is None:
            raise RuntimeError("derive() first")
        nonce = os.urandom(12)
        ct = AESGCM(self.session_key).encrypt(nonce, FINISHED_PLAIN, self.transcript)
        return nonce + ct

    def verify_finished(self, blob: bytes) -> bool:
        """Verify peer Finished message."""
        if self.session_key is None or self.transcript is None:
            raise RuntimeError("derive() first")
        if len(blob) < 12 + 16:
            return False
        nonce, ct = blob[:12], blob[12:]
        try:
            plain = AESGCM(self.session_key).decrypt(nonce, ct, self.transcript)
        except Exception:
            return False
        return plain == FINISHED_PLAIN


@dataclass
class HandshakeResult:
    """Outcome of an offline handshake simulation."""

    success: bool
    alice_ok: bool
    bob_ok: bool
    mitm: bool
    detail: str


def run_honest_handshake() -> HandshakeResult:
    """Simulate Alice ↔ Bob without an adversary."""
    alice = Party("alice")
    bob = Party("bob")
    a_pub = alice.public_bytes
    b_pub = bob.public_bytes
    alice.receive_peer(b_pub)
    bob.receive_peer(a_pub)
    alice.derive(alice_pub=a_pub, bob_pub=b_pub)
    bob.derive(alice_pub=a_pub, bob_pub=b_pub)
    a_fin = alice.finished_message()
    b_fin = bob.finished_message()
    alice_ok = alice.verify_finished(b_fin)
    bob_ok = bob.verify_finished(a_fin)
    ok = alice_ok and bob_ok
    return HandshakeResult(
        success=ok,
        alice_ok=alice_ok,
        bob_ok=bob_ok,
        mitm=False,
        detail="honest handshake verified" if ok else "unexpected verify failure",
    )


def run_mitm_simulation() -> HandshakeResult:
    """Canned MITM: Mallory substitutes her own ephemeral keys.

    Alice thinks she talks to Bob but holds Mallory's key; Bob similarly.
    Finished verification fails on both sides. Offline only — no sockets.
    """
    alice = Party("alice")
    bob = Party("bob")
    mallory_a = Party("mallory-to-alice")
    mallory_b = Party("mallory-to-bob")

    a_pub = alice.public_bytes
    b_pub = bob.public_bytes
    ma_pub = mallory_a.public_bytes
    mb_pub = mallory_b.public_bytes

    # Mallory shows Alice mb_pub as "Bob", and Bob ma_pub as "Alice".
    alice.receive_peer(mb_pub)
    bob.receive_peer(ma_pub)
    # Alice builds transcript with what she believes are the pubs.
    alice.derive(alice_pub=a_pub, bob_pub=mb_pub)
    bob.derive(alice_pub=ma_pub, bob_pub=b_pub)

    # Mallory would need separate sessions; honest Finished won't verify.
    a_fin = alice.finished_message()
    b_fin = bob.finished_message()
    alice_ok = alice.verify_finished(b_fin)
    bob_ok = bob.verify_finished(a_fin)
    return HandshakeResult(
        success=False,
        alice_ok=alice_ok,
        bob_ok=bob_ok,
        mitm=True,
        detail=(
            "MITM simulation: adversary substituted ephemeral public keys; "
            f"alice_verify={alice_ok}, bob_verify={bob_ok} (both should be False)"
        ),
    )


def demo_report(*, include_mitm: bool = True) -> str:
    """Human-readable offline demo report for the CLI."""
    lines = [
        "=== EDUCATIONAL toy handshake demo (offline, in-process) ===",
        "X25519 ephemeral ECDH + HKDF-SHA256 + AES-GCM Finished",
        "NOT TLS / NOT Noise / NO network sockets",
        "",
    ]
    honest = run_honest_handshake()
    lines.append(f"[honest] success={honest.success} alice_ok={honest.alice_ok} bob_ok={honest.bob_ok}")
    lines.append(f"         {honest.detail}")
    if include_mitm:
        mitm = run_mitm_simulation()
        lines.append("")
        lines.append(
            f"[mitm]    success={mitm.success} alice_ok={mitm.alice_ok} bob_ok={mitm.bob_ok}"
        )
        lines.append(f"         {mitm.detail}")
    return "\n".join(lines) + "\n"
