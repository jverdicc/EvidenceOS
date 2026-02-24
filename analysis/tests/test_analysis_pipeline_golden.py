import binascii
import json
import struct
from pathlib import Path

import pytest

from analysis.epistemic_trial.extract_from_capsules import run_extraction

FIXTURE = Path(__file__).parent / "fixtures" / "golden_capsule_records.json"


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


def test_golden_capsule_fixture_extract_and_report(tmp_path: Path) -> None:
    pytest.importorskip("pandas")
    pytest.importorskip("lifelines")
    pytest.importorskip("matplotlib")

    records = json.loads(FIXTURE.read_text(encoding="utf-8"))
    etl_path = _write_etl(tmp_path / "golden.etl", records)

    extracted_path = tmp_path / "capsules.csv"
    rows = run_extraction(etl_path, extracted_path)
    assert extracted_path.exists()
    assert len(rows) == 4

    from analysis.epistemic_trial.report import generate_report

    out_dir = tmp_path / "report"
    artifacts = generate_report(etl_path, out_dir)

    expected_files = {
        "km_by_arm.png",
        "km_success_by_arm.png",
        "cif_primary_by_arm.png",
        "cox_summary.csv",
        "rmst_by_arm.csv",
        "consort_flow.csv",
        "consort_flow.dot",
        "consort_flow.png",
        "summary.json",
    }
    assert expected_files.issubset({p.name for p in out_dir.iterdir()})
    assert all(Path(path).exists() for path in artifacts.__dict__.values())

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["capsules"] == 4
    assert summary["records"] == 5
    assert summary["time_unit"] == "kbits"
    assert summary["event_types"] == {
        "0": "censored",
        "1": "adversary_success",
        "2": "frozen_containment",
        "3": "incident",
    }
    assert set(summary["artifacts"].keys()) == {
        "km_by_arm_png",
        "km_success_by_arm_png",
        "cif_primary_by_arm_png",
        "cox_summary_csv",
        "rmst_csv",
        "consort_plot",
        "consort_csv",
        "consort_dot",
        "summary_json",
    }
