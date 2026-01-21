import tempfile
from pathlib import Path

from evidenceos.etl.store_file import EvidenceTransparencyLog

def test_etl_append_and_verify_inclusion() -> None:
    with tempfile.TemporaryDirectory() as d:
        logdir = Path(d) / "etl"
        EvidenceTransparencyLog.init(logdir)
        log = EvidenceTransparencyLog(logdir)
        entry_hash, sth = log.append({"capsule_root": "sha256:" + "1"*64})
        assert sth["size"] == 1
        assert log.verify_inclusion(entry_hash)

def test_etl_verify_missing_entry_false() -> None:
    with tempfile.TemporaryDirectory() as d:
        logdir = Path(d) / "etl"
        EvidenceTransparencyLog.init(logdir)
        log = EvidenceTransparencyLog(logdir)
        assert not log.verify_inclusion("sha256:" + "0"*64)
