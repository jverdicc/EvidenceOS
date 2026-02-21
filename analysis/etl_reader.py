from __future__ import annotations

import binascii
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class EtlRecord:
    index: int
    payload: bytes


class EtlReaderError(ValueError):
    pass


def _crc32_record(len_bytes: bytes, payload: bytes) -> int:
    return binascii.crc32(len_bytes + payload) & 0xFFFFFFFF


def read_etl_records(path: str | Path) -> list[EtlRecord]:
    p = Path(path)
    data = p.read_bytes()
    records: list[EtlRecord] = []
    pos = 0
    index = 0

    while pos < len(data):
        if pos + 4 > len(data):
            raise EtlReaderError(f"truncated ETL length prefix at byte {pos}")
        len_bytes = data[pos : pos + 4]
        payload_len = int.from_bytes(len_bytes, "little", signed=False)
        pos += 4

        if payload_len < 0 or pos + payload_len + 4 > len(data):
            raise EtlReaderError(
                f"truncated ETL record payload at index {index} (length={payload_len})"
            )

        payload = data[pos : pos + payload_len]
        pos += payload_len
        checksum_bytes = data[pos : pos + 4]
        pos += 4

        expected = int.from_bytes(checksum_bytes, "little", signed=False)
        actual = _crc32_record(len_bytes, payload)
        if expected != actual:
            raise EtlReaderError(
                f"CRC mismatch at ETL index {index}: expected={expected} actual={actual}"
            )

        records.append(EtlRecord(index=index, payload=payload))
        index += 1

    return records


def parse_json_records(records: Iterable[EtlRecord]) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    for record in records:
        try:
            value = json.loads(record.payload.decode("utf-8"))
        except Exception as exc:
            raise EtlReaderError(f"record {record.index} is not valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise EtlReaderError(f"record {record.index} must decode to a JSON object")
        value["_etl_index"] = record.index
        parsed.append(value)
    return parsed
