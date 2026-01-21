from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from evidenceos.common.canonical_json import canonical_dumps_bytes, canonical_dumps_str
from evidenceos.common.hashing import sha256_hex, sha256_prefixed


@dataclass(frozen=True)
class CapsuleManifestEntry:
    path: str
    sha256: str


@dataclass(frozen=True)
class CapsuleManifest:
    version: str
    entries: List[CapsuleManifestEntry]
    build_utc: str

    def to_obj(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "build_utc": self.build_utc,
            "entries": [{"path": e.path, "sha256": e.sha256} for e in self.entries],
        }


class ClaimCapsuleBuilder:
    def __init__(self, *, version: str = "v1"):
        self.version = version

    def build(
        self,
        capsule_dir: Path,
        *,
        contract: Any,
        transcript: Any,
        global_ledger: Any,
        decision_trace: Any,
        build_utc: str,
    ) -> str:
        capsule_dir.mkdir(parents=True, exist_ok=True)

        files: Dict[str, Any] = {
            "contract.json": contract,
            "transcript.json": transcript,
            "global_ledger.json": global_ledger,
            "decision_trace.json": decision_trace,
        }

        entries: List[CapsuleManifestEntry] = []
        for name, obj in files.items():
            p = capsule_dir / name
            p.write_text(canonical_dumps_str(obj), encoding="utf-8")
            entries.append(CapsuleManifestEntry(path=name, sha256=sha256_hex(p.read_bytes())))

        manifest = CapsuleManifest(version=self.version, entries=entries, build_utc=build_utc)
        manifest_path = capsule_dir / "manifest.json"
        manifest_path.write_text(canonical_dumps_str(manifest.to_obj()), encoding="utf-8")

        root = sha256_prefixed(canonical_dumps_bytes(manifest.to_obj()))
        (capsule_dir / "capsule_root.txt").write_text(root + "\n", encoding="utf-8")
        return root


def verify_capsule(capsule_dir: Path) -> None:
    manifest_path = capsule_dir / "manifest.json"
    if not manifest_path.exists():
        raise RuntimeError("missing_manifest")

    manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    # verify manifest root hash
    root = sha256_prefixed(canonical_dumps_bytes(manifest_obj))
    root_file = capsule_dir / "capsule_root.txt"
    if root_file.exists():
        expected = root_file.read_text(encoding="utf-8").strip()
        if expected != root:
            raise RuntimeError("capsule_root_mismatch")

    for entry in manifest_obj.get("entries", []):
        rel = entry["path"]
        expected_sha = entry["sha256"]
        p = capsule_dir / rel
        if not p.exists():
            raise RuntimeError(f"missing_file:{rel}")
        actual = sha256_hex(p.read_bytes())
        if actual != expected_sha:
            raise RuntimeError(f"hash_mismatch:{rel}")
