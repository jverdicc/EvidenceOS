from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from evidenceos.common.hashing import sha256_hex


def leaf_hash(data: bytes) -> str:
    return sha256_hex(b"leaf:" + data)


def node_hash(left: str, right: str) -> str:
    return sha256_hex(("node:" + left + ":" + right).encode("utf-8"))


def build_root(leaves: List[str]) -> str:
    if not leaves:
        return sha256_hex(b"empty")
    level = leaves[:]
    while len(level) > 1:
        nxt: List[str] = []
        for i in range(0, len(level), 2):
            if i + 1 == len(level):
                nxt.append(level[i])
            else:
                nxt.append(node_hash(level[i], level[i + 1]))
        level = nxt
    return level[0]


@dataclass(frozen=True)
class InclusionProof:
    index: int
    siblings: List[Tuple[str, str]]  # (direction, hash) direction in {"L","R"}


def inclusion_proof(index: int, leaves: List[str]) -> InclusionProof:
    if index < 0 or index >= len(leaves):
        raise IndexError("bad index")

    siblings: List[Tuple[str, str]] = []
    idx = index
    level = leaves[:]
    while len(level) > 1:
        nxt: List[str] = []
        for i in range(0, len(level), 2):
            if i + 1 == len(level):
                nxt.append(level[i])
            else:
                nxt.append(node_hash(level[i], level[i + 1]))

            # sibling capture
            if i == idx or i + 1 == idx:
                if i == idx and i + 1 < len(level):
                    siblings.append(("R", level[i + 1]))
                elif i + 1 == idx:
                    siblings.append(("L", level[i]))
        idx = idx // 2
        level = nxt
    return InclusionProof(index=index, siblings=siblings)


def verify_inclusion(leaf: str, proof: InclusionProof, root: str) -> bool:
    acc = leaf
    idx = proof.index
    for direction, sib in proof.siblings:
        if direction == "R":
            acc = node_hash(acc, sib)
        else:
            acc = node_hash(sib, acc)
        idx //= 2
    return acc == root


@dataclass(frozen=True)
class ConsistencyProof:
    old_size: int
    new_size: int
    leaf_hashes: List[str]


def consistency_proof(old_size: int, new_size: int, leaves: List[str]) -> ConsistencyProof:
    if old_size < 0 or new_size < 0:
        raise ValueError("sizes must be >= 0")
    if old_size > new_size:
        raise ValueError("old_size must be <= new_size")
    if new_size > len(leaves):
        raise ValueError("new_size exceeds leaves length")
    # Reference implementation: return the leaf hashes needed to recompute both roots.
    return ConsistencyProof(
        old_size=old_size,
        new_size=new_size,
        leaf_hashes=leaves[:new_size],
    )


def verify_consistency(old_root: str, new_root: str, proof: ConsistencyProof) -> bool:
    if proof.new_size != len(proof.leaf_hashes):
        return False
    old_leaves = proof.leaf_hashes[: proof.old_size]
    new_leaves = proof.leaf_hashes
    return build_root(old_leaves) == old_root and build_root(new_leaves) == new_root
