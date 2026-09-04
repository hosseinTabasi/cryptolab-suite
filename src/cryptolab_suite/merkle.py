"""Merkle tree over SHA-256 leaf hashes with inclusion proofs.

**SAFE construction** for integrity proofs over a fixed leaf set (hash
tree). This is not a blockchain client and does not talk to any network.

Leaf hashing: ``SHA256(0x00 || leaf_data)``.
Internal nodes: ``SHA256(0x01 || left || right)``.
Odd nodes at a level are promoted (duplicated pairing avoided by lifting).

Inclusion proofs are sibling hashes from leaf to root with side flags.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any


LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def hash_leaf(data: bytes) -> bytes:
    """Domain-separated leaf hash."""
    return sha256(LEAF_PREFIX + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    """Domain-separated internal node hash."""
    return sha256(NODE_PREFIX + left + right).digest()


@dataclass(frozen=True)
class InclusionProof:
    """Merkle inclusion proof for one leaf index."""

    leaf_index: int
    leaf_hash: bytes
    siblings: list[tuple[str, bytes]]  # ("L"|"R", sibling_hash)
    root: bytes
    leaf_count: int

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable dict (hex digests)."""
        return {
            "leaf_index": self.leaf_index,
            "leaf_hash": self.leaf_hash.hex(),
            "siblings": [{"side": s, "hash": h.hex()} for s, h in self.siblings],
            "root": self.root.hex(),
            "leaf_count": self.leaf_count,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> InclusionProof:
        """Parse :meth:`to_dict` output."""
        siblings = [(item["side"], bytes.fromhex(item["hash"])) for item in d["siblings"]]
        return cls(
            leaf_index=int(d["leaf_index"]),
            leaf_hash=bytes.fromhex(d["leaf_hash"]),
            siblings=siblings,
            root=bytes.fromhex(d["root"]),
            leaf_count=int(d["leaf_count"]),
        )


@dataclass
class MerkleTree:
    """Binary Merkle tree over leaf data blobs."""

    leaves: list[bytes]
    levels: list[list[bytes]]  # levels[0] = leaf hashes

    @classmethod
    def build(cls, leaves: list[bytes]) -> MerkleTree:
        """Build a tree from raw leaf payloads (hashed with domain sep)."""
        if not leaves:
            raise ValueError("need at least one leaf")
        level = [hash_leaf(x) for x in leaves]
        levels: list[list[bytes]] = [level]
        while len(level) > 1:
            nxt: list[bytes] = []
            i = 0
            while i < len(level):
                if i + 1 < len(level):
                    nxt.append(hash_node(level[i], level[i + 1]))
                    i += 2
                else:
                    # Promote unpaired node (no self-hash duplicate).
                    nxt.append(level[i])
                    i += 1
            levels.append(nxt)
            level = nxt
        return cls(leaves=list(leaves), levels=levels)

    @property
    def root(self) -> bytes:
        """Merkle root digest."""
        return self.levels[-1][0]

    def prove(self, index: int) -> InclusionProof:
        """Generate an inclusion proof for leaf ``index``."""
        if index < 0 or index >= len(self.leaves):
            raise IndexError("leaf index out of range")
        siblings: list[tuple[str, bytes]] = []
        idx = index
        for level in self.levels[:-1]:
            if len(level) == 1:
                break
            if idx % 2 == 0:
                if idx + 1 < len(level):
                    siblings.append(("R", level[idx + 1]))
                # else unpaired — no sibling
            else:
                siblings.append(("L", level[idx - 1]))
            idx //= 2
            # When odd length and we were the last promoted node, index maps
            # to floor(idx) which is already handled by //= 2 for even last.
            # For unpaired last element at odd position? idx is even when last
            # unpaired (index == len-1 and len odd => index even? len=5 idx=4 even).
            # Good.
        return InclusionProof(
            leaf_index=index,
            leaf_hash=self.levels[0][index],
            siblings=siblings,
            root=self.root,
            leaf_count=len(self.leaves),
        )


def verify_inclusion(proof: InclusionProof, leaf_data: bytes | None = None) -> bool:
    """Verify an inclusion proof against its claimed root.

    If ``leaf_data`` is provided, its hash must match ``proof.leaf_hash``.
    """
    if leaf_data is not None:
        if hash_leaf(leaf_data) != proof.leaf_hash:
            return False
    digest = proof.leaf_hash
    for side, sibling in proof.siblings:
        if side == "L":
            digest = hash_node(sibling, digest)
        elif side == "R":
            digest = hash_node(digest, sibling)
        else:
            return False
    return digest == proof.root


def build_from_file(path: str | Path) -> MerkleTree:
    """Build a tree from a text file: one leaf per non-empty line (UTF-8)."""
    text = Path(path).read_text(encoding="utf-8")
    leaves = [line.encode("utf-8") for line in text.splitlines() if line.strip() != ""]
    return MerkleTree.build(leaves)


def save_tree_meta(tree: MerkleTree, path: str | Path) -> Path:
    """Write root + leaf hashes as JSON for CLI use."""
    dest = Path(path)
    payload = {
        "root": tree.root.hex(),
        "leaf_count": len(tree.leaves),
        "leaf_hashes": [h.hex() for h in tree.levels[0]],
        "leaves_hex": [leaf.hex() for leaf in tree.leaves],
    }
    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return dest


def load_tree_meta(path: str | Path) -> MerkleTree:
    """Reload a tree from :func:`save_tree_meta` JSON (rebuilds structure)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    leaves = [bytes.fromhex(h) for h in data["leaves_hex"]]
    return MerkleTree.build(leaves)
