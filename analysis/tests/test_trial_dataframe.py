from pathlib import Path

from analysis.etl_reader import parse_json_records, read_etl_records
from analysis.trial_dataframe import (
    EVENT_CENSORED,
    EVENT_COMPETING,
    EVENT_PRIMARY,
    build_trial_rows,
)
from conftest import build_etl_from_jsonl


def test_event_encoding_on_golden_fixture(tmp_path: Path) -> None:
    fixture_etl = build_etl_from_jsonl(tmp_path / "golden_trial.etl")
    records = parse_json_records(read_etl_records(fixture_etl))
    rows = build_trial_rows(records)

    event_codes = {r.event_code for r in rows}
    assert event_codes == {EVENT_CENSORED, EVENT_PRIMARY, EVENT_COMPETING}
    assert sum(r.event_code == EVENT_PRIMARY for r in rows) == 2
    assert sum(r.event_code == EVENT_COMPETING for r in rows) == 1
    assert sum(r.event_code == EVENT_CENSORED for r in rows) == 1

    assert all("age" in r.covariates for r in rows)
    assert all("bmi" in r.covariates for r in rows)
