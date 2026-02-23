import binascii
import json
import struct
from pathlib import Path

import pandas as pd
import pytest

from analysis.epistemic_trial.extract_from_capsules import (
    EVENT_ADVERSARY_SUCCESS,
    EVENT_CENSORED,
    EVENT_FROZEN_CONTAINMENT,
    EVENT_INCIDENT,
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


def _capsule(idx: int, intervention: str, *, decision: int = 1, certified: bool = True, frozen: bool = False, state: str = "ACTIVE", canary_incident: bool = False) -> dict:
    return {
        "schema": "evidenceos.v2.claim_capsule",
        "claim_id_hex": f"claim-{idx}",
        "topic_id_hex": "topic-1",
        "ledger": {"k_bits_total": float(idx + 1), "frozen": frozen},
        "trial_arm_id": idx % 2,
        "trial_intervention_id": intervention,
        "lane": "red",
        "oracle_id_hex": f"oracle-{idx%2}",
        "adversary_type": "none",
        "holdout_ref": "h1",
        "holdout_bucket": f"b{idx%2}",
        "nullspec_id_hex": f"N{idx%2}",
        "decision": decision,
        "certified": certified,
        "state": state,
        "canary_incident": canary_incident,
    }


def test_generate_report_outputs_exist(tmp_path: Path) -> None:
    pytest.importorskip("pandas")
    pytest.importorskip("lifelines")
    pytest.importorskip("matplotlib")

    from analysis.epistemic_trial.report import generate_report

    etl_path = _write_etl(
        tmp_path / "trial.etl",
        [
            {"schema": "evidenceos.v2.preflight", "eligible": True},
            _capsule(1, "A", decision=1, certified=False),  # adversary success
            _capsule(2, "A", frozen=True),  # frozen
            _capsule(3, "B", state="REVOKED"),  # incident
            _capsule(4, "B", decision=1, certified=True),  # censored
        ],
    )

    out_dir = tmp_path / "report"
    artifacts = generate_report(etl_path, out_dir)

    for path in artifacts.__dict__.values():
        assert Path(path).exists(), path

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["capsules"] == 4
    assert sorted(summary["arms"]) == ["A", "B"]
    assert summary["time_unit"] == "kbits"


def test_synthetic_fixture_cif_monotone_and_consort_counts(tmp_path: Path) -> None:
    pytest.importorskip("pandas")
    pytest.importorskip("lifelines")
    pytest.importorskip("matplotlib")

    from analysis.epistemic_trial.extract_from_capsules import extract_capsule_rows
    from analysis.epistemic_trial.report import _build_dataframe
    from lifelines import AalenJohansenFitter

    records = [
        {"schema": "evidenceos.v2.preflight", "eligible": True},
        _capsule(1, "A", decision=1, certified=False),
        _capsule(2, "A", frozen=True),
        _capsule(3, "B", state="REVOKED"),
        _capsule(4, "B", decision=1, certified=True),
    ]
    etl_path = _write_etl(tmp_path / "trial_synth.etl", records)

    from analysis.epistemic_trial.report import generate_report

    out_dir = tmp_path / "report_synth"
    generate_report(etl_path, out_dir)

    rows = extract_capsule_rows(records)
    event_types = [r["event_type"] for r in rows]
    assert EVENT_ADVERSARY_SUCCESS in event_types
    assert EVENT_FROZEN_CONTAINMENT in event_types
    assert EVENT_INCIDENT in event_types
    assert EVENT_CENSORED in event_types

    df = _build_dataframe(rows)
    for _, arm_df in df.groupby("intervention_id"):
        ajf = AalenJohansenFitter()
        ajf.fit(arm_df["time"], arm_df["event_type"], event_of_interest=EVENT_ADVERSARY_SUCCESS)
        cif_vals = ajf.cumulative_density_.iloc[:, 0].to_list()
        assert all(y >= x for x, y in zip(cif_vals, cif_vals[1:]))

    consort = pd.read_csv(out_dir / "consort_flow.csv")
    counts = dict(zip(consort["stage"], consort["count"]))
    assert counts["claim_capsules"] == 4
    assert counts["event_adversary_success"] == 1
    assert counts["event_frozen_containment"] == 1
    assert counts["event_incident"] == 1
    assert counts["event_censored"] == 1
