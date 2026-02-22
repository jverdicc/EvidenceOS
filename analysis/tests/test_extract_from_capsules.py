import binascii
import json
import struct
from pathlib import Path

import pytest

from analysis.epistemic_trial.extract_from_capsules import (
    CapsuleExtractionError,
    run_extraction,
)


def _write_etl(path: Path, records: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as out:
        for rec in records:
            payload = json.dumps(rec, separators=(",", ":")).encode("utf-8")
            ln = struct.pack("<I", len(payload))
            crc = binascii.crc32(ln + payload) & 0xFFFFFFFF
            out.write(ln)
            out.write(payload)
            out.write(struct.pack("<I", crc))
    return path


def _capsule(
    claim_id: str,
    k_bits_total: float,
    decision: int = 1,
    frozen: bool | None = None,
    state: str | None = None,
):
    ledger = {"k_bits_total": k_bits_total}
    if frozen is not None:
        ledger["frozen"] = frozen
    record = {
        "schema": "evidenceos.v2.claim_capsule",
        "claim_id_hex": claim_id,
        "topic_id_hex": "topic-1",
        "ledger": ledger,
        "decision": decision,
        "trial_arm_id": 2,
        "trial_intervention_id": "arm-A",
        "trial_nonce_hex": "0a0b",
        "holdout_ref": "hold-ref",
        "holdout_handle_hash_hex": "abcd",
        "nullspec_id_hex": "nullspec-1",
    }
    if state is not None:
        record["state"] = state
    return record


def test_extractor_emits_kbits_and_frozen(tmp_path: Path) -> None:
    etl = _write_etl(
        tmp_path / "capsules.etl",
        [
            _capsule("c1", 12.5, decision=1, frozen=False),
            _capsule("c2", 3.0, decision=3, frozen=True),
        ],
    )
    out = tmp_path / "capsules.csv"
    rows = run_extraction(etl, out)

    assert len(rows) == 2
    assert rows[0]["k_bits_total"] == 12.5
    assert rows[0]["frozen_event"] == 0
    assert rows[1]["k_bits_total"] == 3.0
    assert rows[1]["frozen_event"] == 1
    assert out.exists()


def test_extractor_treats_frozen_state_as_event_when_ledger_flag_missing(tmp_path: Path) -> None:
    etl = _write_etl(
        tmp_path / "capsules-frozen-state.etl",
        [_capsule("c4", 9.0, decision=1, frozen=None, state="FROZEN")],
    )
    out = tmp_path / "capsules-frozen-state.csv"
    rows = run_extraction(etl, out)

    assert len(rows) == 1
    assert rows[0]["frozen_event"] == 1
    assert rows[0]["outcome"] == "FROZEN"


def test_missing_required_field_fails_closed(tmp_path: Path) -> None:
    broken = _capsule("c3", 1.0)
    del broken["ledger"]["k_bits_total"]
    etl = _write_etl(tmp_path / "broken.etl", [broken])

    with pytest.raises(CapsuleExtractionError, match="missing required field: ledger.k_bits_total"):
        run_extraction(etl, tmp_path / "broken.csv")
