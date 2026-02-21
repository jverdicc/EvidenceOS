import binascii
import json
import struct
from pathlib import Path

import pytest


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


def _capsule(idx: int, frozen: bool, intervention: str, nullspec: str) -> dict:
    return {
        "schema": "evidenceos.v2.claim_capsule",
        "claim_id_hex": f"claim-{idx}",
        "topic_id_hex": "topic-1",
        "ledger": {"k_bits_total": float(idx + 1), "frozen": frozen},
        "trial_arm_id": idx % 2,
        "trial_intervention_id": intervention,
        "lane": "red",
        "adversary_type": "none",
        "holdout_ref": "h1",
        "nullspec_id_hex": nullspec,
    }


def test_generate_report_outputs_exist(tmp_path: Path) -> None:
    pytest.importorskip("pandas")
    pytest.importorskip("lifelines")
    pytest.importorskip("matplotlib")
    pytest.importorskip("scipy")

    from analysis.epistemic_trial.report import generate_report

    etl_path = _write_etl(
        tmp_path / "trial.etl",
        [
            {"schema": "evidenceos.v2.preflight", "eligible": True},
            _capsule(1, True, "A", "N1"),
            _capsule(2, False, "A", "N1"),
            _capsule(3, True, "B", "N2"),
            _capsule(4, False, "B", "N2"),
        ],
    )

    out_dir = tmp_path / "report"
    artifacts = generate_report(etl_path, out_dir)

    for path in artifacts.__dict__.values():
        assert Path(path).exists(), path

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["capsules"] == 4
    assert sorted(summary["arms"]) == ["A", "B"]
