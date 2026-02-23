#!/usr/bin/env python3
"""Security-doc drift checks for holdout encryption and TEE docs."""

from __future__ import annotations

from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_STATUS = REPO_ROOT / "docs" / "IMPLEMENTATION_STATUS.md"

DOCS_TO_CODE_REFS: dict[Path, tuple[str, ...]] = {
    REPO_ROOT / "docs" / "HOLDOUT_ENCRYPTION.md": (
        "crates/evidenceos-core/src/holdout_crypto.rs",
        "crates/evidenceos-daemon/src/server/core.rs",
        "crates/evidenceos-daemon/src/main.rs",
    ),
    REPO_ROOT / "docs" / "TEE.md": (
        "crates/evidenceos-core/src/tee.rs",
        "crates/evidenceos-daemon/src/server/core.rs",
    ),
}

CONTRADICTION_PATTERNS = (
    re.compile(r"\bstub(s)?\b", re.IGNORECASE),
    re.compile(r"\bplaceholder\b", re.IGNORECASE),
    re.compile(r"\bnot implemented\b", re.IGNORECASE),
    re.compile(r"\binterface-only\b", re.IGNORECASE),
)


class DriftFailure(RuntimeError):
    pass


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _ensure_path_exists(rel_path: str) -> None:
    if not (REPO_ROOT / rel_path).exists():
        raise DriftFailure(f"doc references missing path: {rel_path}")


def _status_mentions(feature_hint: str) -> bool:
    status = _read(IMPLEMENTATION_STATUS).lower()
    return feature_hint.lower() in status


def check_required_code_references() -> None:
    for doc_path, refs in DOCS_TO_CODE_REFS.items():
        doc = _read(doc_path)
        for rel in refs:
            if rel not in doc:
                raise DriftFailure(f"{doc_path.relative_to(REPO_ROOT)} missing code reference: {rel}")
            _ensure_path_exists(rel)


def check_no_known_contradiction_phrases() -> None:
    for doc_path in DOCS_TO_CODE_REFS:
        doc = _read(doc_path)
        for pattern in CONTRADICTION_PATTERNS:
            if pattern.search(doc):
                raise DriftFailure(
                    f"{doc_path.relative_to(REPO_ROOT)} contains contradiction-prone phrase matching /{pattern.pattern}/"
                )


def check_impl_status_entries_present() -> None:
    if not IMPLEMENTATION_STATUS.exists():
        raise DriftFailure("docs/IMPLEMENTATION_STATUS.md is required")
    required = (
        "holdout",
        "tee",
    )
    for feature in required:
        if not _status_mentions(feature):
            raise DriftFailure(
                f"docs/IMPLEMENTATION_STATUS.md must mention feature '{feature}' for doc-drift auditing"
            )


def main() -> int:
    try:
        check_impl_status_entries_present()
        check_required_code_references()
        check_no_known_contradiction_phrases()
    except DriftFailure as exc:
        print(f"doc drift check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
