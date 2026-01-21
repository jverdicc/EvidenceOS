from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from evidenceos.common.canonical_json import canonical_dumps_bytes, canonical_dumps_str
from evidenceos.common.hashing import sha256_prefixed
from .merkle import InclusionProof, build_root, inclusion_proof, leaf_hash, verify_inclusion


@dataclass(frozen=True)
class SignedTreeHead:
    size: int
    root: str
    sth_hash: str


class EvidenceTransparencyLog:
    """A simple file-backed ETL store.

    This is a reference implementation:
    - entries.jsonl append-only
    - sth.json overwritten with latest tree head
    """

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.entries_path = log_dir / "entries.jsonl"
        self.sth_path = log_dir / "sth.json"

    @staticmethod
    def init(log_dir: Path) -> None:
        log_dir.mkdir(parents=True, exist_ok=True)
        entries = log_dir / "entries.jsonl"
        if not entries.exists():
            entries.write_text("", encoding="utf-8")
        sth = log_dir / "sth.json"
        if not sth.exists():
            sth.write_text(canonical_dumps_str({"size": 0, "root": "", "sth_hash": ""}), encoding="utf-8")

    def _read_entries(self) -> List[Dict[str, Any]]:
        if not self.entries_path.exists():
            raise RuntimeError("etl_not_initialized")
        lines = self.entries_path.read_text(encoding="utf-8").splitlines()
        out: List[Dict[str, Any]] = []
        for ln in lines:
            if ln.strip():
                out.append(json.loads(ln))
        return out

    def _write_sth(self, sth: SignedTreeHead) -> None:
        self.sth_path.write_text(canonical_dumps_str({"size": sth.size, "root": sth.root, "sth_hash": sth.sth_hash}), encoding="utf-8")

    def get_sth(self) -> SignedTreeHead:
        if not self.sth_path.exists():
            raise RuntimeError("etl_not_initialized")
        obj = json.loads(self.sth_path.read_text(encoding="utf-8"))
        return SignedTreeHead(size=obj["size"], root=obj["root"], sth_hash=obj["sth_hash"])

    def append(self, entry_obj: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        entries = self._read_entries()
        entry_hash = sha256_prefixed(canonical_dumps_bytes(entry_obj))
        rec = {"entry_hash": entry_hash, "entry": entry_obj}
        with self.entries_path.open("a", encoding="utf-8") as f:
            f.write(canonical_dumps_str(rec) + "\n")

        # recompute STH
        entries2 = self._read_entries()
        leaves = [leaf_hash(canonical_dumps_bytes(e["entry"])) for e in entries2]
        root = build_root(leaves)
        sth_obj = {"size": len(leaves), "root": root}
        sth_hash = sha256_prefixed(canonical_dumps_bytes(sth_obj))
        sth = SignedTreeHead(size=len(leaves), root=root, sth_hash=sth_hash)
        self._write_sth(sth)
        return entry_hash, {"size": sth.size, "root": sth.root, "sth_hash": sth.sth_hash}

    def prove_inclusion(self, entry_hash: str) -> InclusionProof:
        entries = self._read_entries()
        idx = None
        for i, rec in enumerate(entries):
            if rec["entry_hash"] == entry_hash:
                idx = i
                break
        if idx is None:
            raise KeyError("entry_hash_not_found")
        leaves = [leaf_hash(canonical_dumps_bytes(e["entry"])) for e in entries]
        return inclusion_proof(idx, leaves)

    def verify_inclusion(self, entry_hash: str) -> bool:
        entries = self._read_entries()
        idx = None
        leaf = None
        for i, rec in enumerate(entries):
            if rec["entry_hash"] == entry_hash:
                idx = i
                leaf = leaf_hash(canonical_dumps_bytes(rec["entry"]))
                break
        if idx is None or leaf is None:
            return False
        sth = self.get_sth()
        proof = self.prove_inclusion(entry_hash)
        return verify_inclusion(leaf, proof, sth.root)
