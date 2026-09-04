"""Offline CTF-style challenge lab (canned ciphertexts only).

**EDUCATIONAL.** Challenges reuse classical-cipher concepts from
cryptolab-kit (Caesar, Vigenère, frequency). Solutions are checked
locally; no network I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


@dataclass(frozen=True)
class Challenge:
    """One offline learning challenge."""

    id: str
    title: str
    difficulty: str
    description: str
    ciphertext: str
    hint: str
    # SHA-256 hex of the normalized plaintext answer (uppercased letters+spaces collapsed).
    answer_digest: str


def _normalize(text: str) -> str:
    """Normalize for answer checking: uppercase, collapse whitespace."""
    return " ".join(text.upper().split())


def _digest(text: str) -> str:
    return sha256(_normalize(text).encode("utf-8")).hexdigest()


# Answers are NOT stored in plaintext; only digests. Ciphertexts are canned.
# challenge-01: Caesar shift 7 → "CRYPTOGRAPHY IS FUN"
# challenge-02: Vigenère key LEMON → "ATTACK AT DAWN"
# challenge-03: Caesar with frequency — known canned English fragment
_CHALLENGES: list[Challenge] = [
    Challenge(
        id="chal-01",
        title="Caesar warm-up",
        difficulty="easy",
        description=(
            "EDUCATIONAL. Decrypt this Caesar ciphertext. Letters only; "
            "spaces preserved. The shift is a small integer."
        ),
        ciphertext="JYFWAVNYHWOF PZ MBU",
        hint="Try shift=7, or brute-force 26 keys.",
        answer_digest=_digest("CRYPTOGRAPHY IS FUN"),
    ),
    Challenge(
        id="chal-02",
        title="Vigenère lemon",
        difficulty="medium",
        description=(
            "EDUCATIONAL. Decrypt with a classic repeating key. "
            "Key material is a citrus fruit often used in textbooks."
        ),
        ciphertext="LXFOPV EF RNHR",
        hint="Key = LEMON (case-insensitive).",
        answer_digest=_digest("ATTACK AT DAWN"),
    ),
    Challenge(
        id="chal-03",
        title="Frequency fragment",
        difficulty="medium",
        description=(
            "EDUCATIONAL. A Caesar-encrypted English sentence. Use letter "
            "frequency / chi-squared ranking (cryptolab-kit style) to recover "
            "the shift. Submit the full recovered plaintext."
        ),
        # shift=4 of a short English sentence
        ciphertext="XLI EVX SJ GVCTXSKVETLC MW E WGMIRGI ERH ER EVX.",
        hint="Most common English letter is E; try cryptolab frequency tools.",
        answer_digest=_digest("THE ART OF CRYPTOGRAPHY IS A SCIENCE AND AN ART."),
    ),
]


def list_challenges() -> list[Challenge]:
    """Return all challenges."""
    return list(_CHALLENGES)


def get_challenge(challenge_id: str) -> Challenge:
    """Look up a challenge by id."""
    for c in _CHALLENGES:
        if c.id == challenge_id:
            return c
    raise KeyError(f"unknown challenge id: {challenge_id}")


def check_answer(challenge_id: str, answer: str) -> bool:
    """Return True if ``answer`` matches the canned solution digest."""
    chal = get_challenge(challenge_id)
    return _digest(answer) == chal.answer_digest


def format_list() -> str:
    """Human-readable challenge catalogue."""
    lines = ["Offline challenge lab (EDUCATIONAL, canned only)", ""]
    for c in _CHALLENGES:
        lines.append(f"  {c.id}  [{c.difficulty}]  {c.title}")
        lines.append(f"         {c.description}")
        lines.append(f"         ciphertext: {c.ciphertext}")
        lines.append("")
    lines.append("Solve:  suite challenge solve <id> --answer '...'")
    return "\n".join(lines) + "\n"


def caesar_decrypt_local(ciphertext: str, shift: int) -> str:
    """Tiny local Caesar decrypt so chal-01/03 work without kit."""
    out: list[str] = []
    shift %= 26
    for ch in ciphertext:
        if "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 - shift) % 26 + 65))
        elif "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 - shift) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def vigenere_decrypt_local(ciphertext: str, key: str) -> str:
    """Tiny local Vigenère decrypt so chal-02 works without kit."""
    shifts: list[int] = []
    for ch in key:
        if "A" <= ch <= "Z":
            shifts.append(ord(ch) - 65)
        elif "a" <= ch <= "z":
            shifts.append(ord(ch) - 97)
    if not shifts:
        raise ValueError("key must contain letters")
    out: list[str] = []
    i = 0
    for ch in ciphertext:
        if "A" <= ch <= "Z":
            s = (ord(ch) - 65 - shifts[i % len(shifts)]) % 26
            out.append(chr(s + 65))
            i += 1
        elif "a" <= ch <= "z":
            s = (ord(ch) - 97 - shifts[i % len(shifts)]) % 26
            out.append(chr(s + 97))
            i += 1
        else:
            out.append(ch)
    return "".join(out)
