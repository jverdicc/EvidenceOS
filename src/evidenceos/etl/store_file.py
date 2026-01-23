from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from evidenceos.common.canonical_json import canonical_dumps_bytes, canonical_dumps_str
from evidenceos.common.hashing import sha256_prefixed
from evidenceos.common.signing import Ed25519Keypair, sign_ed25519, verify_ed25519
from .merkle import (
    ConsistencyProof,
    InclusionProof,
    build_root,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    verify_consistency,
    verify_inclusion,
)


@dataclass(frozen=True)
class SignedTreeHead:
    size: int
    root: str
    sth_hash: str
    signature: str
    public_key: str


class EvidenceTransparencyLog:
    """A simple file-backed ETL store.

    This is a reference implementation:
    - entries.jsonl append-only
    - sth.json overwritten with latest tree head
    """

    def __init__(self, log_dir: Path, *, keypair: Ed25519Keypair | None = None):
        self.log_dir = log_dir
        self.entries_path = log_dir / "entries.jsonl"
        self.sth_path = log_dir / "sth.json"
        self.keypair = keypair

    @staticmethod
    def init(log_dir: Path) -> None:
        log_dir.mkdir(parents=True, exist_ok=True)
        entries = log_dir / "entries.jsonl"
        if not entries.exists():
            entries.write_text("", encoding="utf-8")
        sth = log_dir / "sth.json"
        if not sth.exists():
            sth.write_text(
                canonical_dumps_str(
                    {
                        "size": 0,
                        "root": "",
                        "sth_hash": "",
                        "signature": "",
                        "public_key": "",
                    }
                ),
                encoding="utf-8",
            )

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
        self.sth_path.write_text(
            canonical_dumps_str(
                {
                    "size": sth.size,
                    "root": sth.root,
                    "sth_hash": sth.sth_hash,
                    "signature": sth.signature,
                    "public_key": sth.public_key,
                }
            ),
            encoding="utf-8",
        )

    def get_sth(self) -> SignedTreeHead:
        if not self.sth_path.exists():
            raise RuntimeError("etl_not_initialized")
        obj = json.loads(self.sth_path.read_text(encoding="utf-8"))
        return SignedTreeHead(
            size=obj["size"],
            root=obj["root"],
            sth_hash=obj["sth_hash"],
            signature=obj.get("signature", ""),
            public_key=obj.get("public_key", ""),
        )

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
        signature = ""
        public_key = ""
        if self.keypair is not None:
            signature = sign_ed25519(self.keypair, sth_obj)
            public_key = "ed25519:" + self.keypair.public_key_bytes().hex()
        sth = SignedTreeHead(
            size=len(leaves),
            root=root,
            sth_hash=sth_hash,
            signature=signature,
            public_key=public_key,
        )
        self._write_sth(sth)
        return entry_hash, {
            "size": sth.size,
            "root": sth.root,
            "sth_hash": sth.sth_hash,
            "signature": sth.signature,
            "public_key": sth.public_key,
        }

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

    def prove_consistency(self, old_size: int, new_size: int) -> ConsistencyProof:
        entries = self._read_entries()
        leaves = [leaf_hash(canonical_dumps_bytes(e["entry"])) for e in entries]
        return consistency_proof(old_size, new_size, leaves)

    def verify_consistency(self, old_root: str, proof: ConsistencyProof) -> bool:
        sth = self.get_sth()
        if sth.size != proof.new_size:
            return False
        return verify_consistency(old_root, sth.root, proof)

    def verify_sth_signature(self) -> bool:
        sth = self.get_sth()
        if not sth.signature or not sth.public_key:
            return False
        if not sth.public_key.startswith("ed25519:"):
            return False
        public_key_bytes = bytes.fromhex(sth.public_key.split(":", 1)[1])
        payload = {"size": sth.size, "root": sth.root}
        return verify_ed25519(public_key_bytes, payload, sth.signature)
