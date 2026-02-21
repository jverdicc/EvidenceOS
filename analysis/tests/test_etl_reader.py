from pathlib import Path

import pytest

from analysis.etl_reader import EtlReaderError, parse_json_records, read_etl_records
from conftest import build_etl_from_jsonl


def test_reads_fixture_and_validates_crc(tmp_path: Path) -> None:
    fixture_etl = build_etl_from_jsonl(tmp_path / "golden_trial.etl")
    records = read_etl_records(fixture_etl)
    assert len(records) == 4
    parsed = parse_json_records(records)
    assert parsed[0]["participant_id"] == "p1"


def test_crc_failure_rejected(tmp_path: Path) -> None:
    fixture_etl = build_etl_from_jsonl(tmp_path / "golden_trial.etl")
    bad = tmp_path / "bad.etl"
    raw = bytearray(fixture_etl.read_bytes())
    raw[-1] ^= 0x01
    bad.write_bytes(raw)
    with pytest.raises(EtlReaderError, match="CRC mismatch"):
        read_etl_records(bad)
