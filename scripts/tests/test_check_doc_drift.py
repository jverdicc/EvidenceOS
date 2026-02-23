import tempfile
import unittest
from pathlib import Path

from scripts import check_doc_drift as drift


class CheckDocDriftTests(unittest.TestCase):
    def test_detects_missing_code_reference(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            status = root / "docs" / "IMPLEMENTATION_STATUS.md"
            status.parent.mkdir(parents=True, exist_ok=True)
            status.write_text("| Feature | holdout | tee |\n", encoding="utf-8")

            doc = root / "docs" / "TEE.md"
            doc.write_text("# TEE\n", encoding="utf-8")
            code = root / "crates" / "evidenceos-core" / "src" / "tee.rs"
            code.parent.mkdir(parents=True, exist_ok=True)
            code.write_text("// ok", encoding="utf-8")

            old_root = drift.REPO_ROOT
            old_map = drift.DOCS_TO_CODE_REFS
            old_status = drift.IMPLEMENTATION_STATUS
            try:
                drift.REPO_ROOT = root
                drift.IMPLEMENTATION_STATUS = status
                drift.DOCS_TO_CODE_REFS = {doc: ("crates/evidenceos-core/src/tee.rs", "crates/evidenceos-daemon/src/server/core.rs")}
                with self.assertRaises(drift.DriftFailure):
                    drift.check_required_code_references()
            finally:
                drift.REPO_ROOT = old_root
                drift.DOCS_TO_CODE_REFS = old_map
                drift.IMPLEMENTATION_STATUS = old_status

    def test_rejects_contradiction_phrase(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            status = root / "docs" / "IMPLEMENTATION_STATUS.md"
            status.parent.mkdir(parents=True, exist_ok=True)
            status.write_text("holdout tee", encoding="utf-8")
            doc = root / "docs" / "HOLDOUT_ENCRYPTION.md"
            doc.write_text("contains placeholder text\ncrates/evidenceos-core/src/holdout_crypto.rs", encoding="utf-8")
            code = root / "crates" / "evidenceos-core" / "src" / "holdout_crypto.rs"
            code.parent.mkdir(parents=True, exist_ok=True)
            code.write_text("// ok", encoding="utf-8")

            old_root = drift.REPO_ROOT
            old_map = drift.DOCS_TO_CODE_REFS
            old_status = drift.IMPLEMENTATION_STATUS
            try:
                drift.REPO_ROOT = root
                drift.IMPLEMENTATION_STATUS = status
                drift.DOCS_TO_CODE_REFS = {doc: ("crates/evidenceos-core/src/holdout_crypto.rs",)}
                with self.assertRaises(drift.DriftFailure):
                    drift.check_no_known_contradiction_phrases()
            finally:
                drift.REPO_ROOT = old_root
                drift.DOCS_TO_CODE_REFS = old_map
                drift.IMPLEMENTATION_STATUS = old_status


if __name__ == "__main__":
    unittest.main()
