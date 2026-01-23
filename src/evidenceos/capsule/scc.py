from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from evidenceos.common.canonical_json import canonical_dumps_bytes, canonical_dumps_str
from evidenceos.common.hashing import sha256_hex, sha256_prefixed
from evidenceos.common.signing import Ed25519Keypair, sign_ed25519, verify_ed25519


@dataclass(frozen=True)
class SCCManifestEntry:
    path: str
    sha256: str


@dataclass(frozen=True)
class SCCManifest:
    version: str
    entries: List[SCCManifestEntry]
    build_utc: str

    def to_obj(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "build_utc": self.build_utc,
            "entries": [{"path": e.path, "sha256": e.sha256} for e in self.entries],
        }


class StandardizedClaimCapsuleBuilder:
    def __init__(self, *, version: str = "scc-v1") -> None:
        self.version = version

    def build(
        self,
        capsule_dir: Path,
        *,
        claim: Any,
        safety_case: Any,
        reality_kernel_inputs: Any,
        uvp_transcript: Any,
        ewl: Any,
        decision_trace: Any,
        build_utc: str,
        signing_keypair: Ed25519Keypair | None = None,
    ) -> str:
        capsule_dir.mkdir(parents=True, exist_ok=True)

        files: Dict[str, Any] = {
            "claim.json": claim,
            "safety_case.json": safety_case,
            "reality_kernel.json": reality_kernel_inputs,
            "uvp_transcript.json": uvp_transcript,
            "ewl.json": ewl,
            "decision_trace.json": decision_trace,
        }

        entries: List[SCCManifestEntry] = []
        for name, obj in files.items():
            path = capsule_dir / name
            path.write_text(canonical_dumps_str(obj), encoding="utf-8")
            entries.append(SCCManifestEntry(path=name, sha256=sha256_hex(path.read_bytes())))

        manifest = SCCManifest(version=self.version, entries=entries, build_utc=build_utc)
        manifest_path = capsule_dir / "manifest.json"
        manifest_path.write_text(canonical_dumps_str(manifest.to_obj()), encoding="utf-8")

        root = sha256_prefixed(canonical_dumps_bytes(manifest.to_obj()))
        (capsule_dir / "capsule_root.txt").write_text(root + "\n", encoding="utf-8")
        if signing_keypair is not None:
            signature = sign_ed25519(signing_keypair, manifest.to_obj())
            sig_obj = {
                "public_key": "ed25519:" + signing_keypair.public_key_bytes().hex(),
                "signature": signature,
            }
            (capsule_dir / "capsule_signature.json").write_text(
                canonical_dumps_str(sig_obj),
                encoding="utf-8",
            )
        return root


def verify_scc(capsule_dir: Path) -> None:
    manifest_path = capsule_dir / "manifest.json"
    if not manifest_path.exists():
        raise RuntimeError("missing_manifest")

    manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = sha256_prefixed(canonical_dumps_bytes(manifest_obj))
    root_file = capsule_dir / "capsule_root.txt"
    if root_file.exists():
        expected = root_file.read_text(encoding="utf-8").strip()
        if expected != root:
            raise RuntimeError("capsule_root_mismatch")

    for entry in manifest_obj.get("entries", []):
        rel = entry["path"]
        expected_sha = entry["sha256"]
        path = capsule_dir / rel
        if not path.exists():
            raise RuntimeError(f"missing_file:{rel}")
        actual = sha256_hex(path.read_bytes())
        if actual != expected_sha:
            raise RuntimeError(f"hash_mismatch:{rel}")

    sig_path = capsule_dir / "capsule_signature.json"
    if sig_path.exists():
        sig_obj = json.loads(sig_path.read_text(encoding="utf-8"))
        public_key = sig_obj.get("public_key", "")
        signature = sig_obj.get("signature", "")
        if not public_key.startswith("ed25519:"):
            raise RuntimeError("invalid_capsule_signature")
        public_key_bytes = bytes.fromhex(public_key.split(":", 1)[1])
        if not verify_ed25519(public_key_bytes, manifest_obj, signature):
            raise RuntimeError("invalid_capsule_signature")


__all__ = ["StandardizedClaimCapsuleBuilder", "verify_scc"]
