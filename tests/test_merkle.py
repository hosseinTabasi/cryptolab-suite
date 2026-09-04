"""Tests for Merkle tree inclusion proofs."""

from __future__ import annotations

from cryptolab_suite.merkle import MerkleTree, hash_leaf, verify_inclusion


def test_single_leaf() -> None:
    tree = MerkleTree.build([b"only"])
    assert tree.root == hash_leaf(b"only")
    proof = tree.prove(0)
    assert verify_inclusion(proof, b"only")


def test_odd_leaf_count() -> None:
    leaves = [f"leaf-{i}".encode() for i in range(5)]
    tree = MerkleTree.build(leaves)
    for i, leaf in enumerate(leaves):
        proof = tree.prove(i)
        assert verify_inclusion(proof, leaf)
        assert not verify_inclusion(proof, b"tampered")


def test_power_of_two() -> None:
    leaves = [b"a", b"b", b"c", b"d"]
    tree = MerkleTree.build(leaves)
    for i in range(4):
        assert verify_inclusion(tree.prove(i), leaves[i])
