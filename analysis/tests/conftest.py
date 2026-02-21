import binascii
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURE_JSONL = Path(__file__).parent / "fixtures" / "golden_trial.jsonl"


def build_etl_from_jsonl(target_path: Path) -> Path:
    """Build a binary ETL file from newline-delimited JSON records."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with FIXTURE_JSONL.open("r", encoding="utf-8") as src, target_path.open("wb") as out:
        for line in src:
            line = line.strip()
            if not line:
                continue
            payload = json.dumps(json.loads(line), separators=(",", ":")).encode("utf-8")
            ln = struct.pack("<I", len(payload))
            crc = binascii.crc32(ln + payload) & 0xFFFFFFFF
            out.write(ln)
            out.write(payload)
            out.write(struct.pack("<I", crc))
    return target_path
