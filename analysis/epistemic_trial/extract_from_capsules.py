from __future__ import annotations

import argparse
import base64
import csv
from pathlib import Path
from typing import Any

from analysis.etl_reader import parse_json_records, read_etl_records


class CapsuleExtractionError(ValueError):
    pass


_REQUIRED_COLUMNS = [
    "claim_id",
    "ended_at",
    "arm_id",
    "intervention_id",
    "trial_nonce_b64",
    "k_bits_total",
    "frozen_event",
    "censored",
    "lane",
    "adversary_type",
    "holdout_ref",
    "holdout_handle",
    "topic_id",
    "nullspec_id",
    "outcome",
]


def _require(payload: dict[str, Any], path: str, etl_index: int) -> Any:
    cur: Any = payload
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            raise CapsuleExtractionError(
                f"capsule at ETL index {etl_index} missing required field: {path}"
            )
    return cur


def _normalize_trial_nonce_b64(trial_nonce_hex: Any, etl_index: int) -> str | None:
    if trial_nonce_hex is None:
        return None
    if not isinstance(trial_nonce_hex, str):
        raise CapsuleExtractionError(
            f"capsule at ETL index {etl_index} has non-string trial_nonce_hex"
        )
    try:
        return base64.b64encode(bytes.fromhex(trial_nonce_hex)).decode("ascii")
    except ValueError as exc:
        raise CapsuleExtractionError(
            f"capsule at ETL index {etl_index} has invalid trial_nonce_hex"
        ) from exc


def _settlement_outcome(capsule: dict[str, Any], frozen: bool) -> str:
    if frozen:
        return "FROZEN"
    decision = capsule.get("decision")
    certified = bool(capsule.get("certified"))
    state = str(capsule.get("state", "")).upper()
    if decision == 1:
        return "PASS" if certified else "FAIL"
    if decision == 2:
        return "REJECT"
    if decision == 3:
        return "HEAVY"
    if state in {"REVOKED", "TAINTED", "STALE"}:
        return "FAIL"
    return "FAIL"


def extract_capsule_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        if record.get("schema") != "evidenceos.v2.claim_capsule":
            continue
        etl_index = int(record.get("_etl_index", -1))
        claim_id = _require(record, "claim_id_hex", etl_index)
        topic_id = _require(record, "topic_id_hex", etl_index)
        ledger = _require(record, "ledger", etl_index)
        if not isinstance(ledger, dict):
            raise CapsuleExtractionError(f"capsule at ETL index {etl_index} has invalid ledger")
        k_bits_total = _require(record, "ledger.k_bits_total", etl_index)
        frozen_raw = ledger.get("frozen")
        if frozen_raw is None:
            frozen = bool(record.get("decision") == 3 or str(record.get("state", "")).upper() == "FROZEN")
        elif isinstance(frozen_raw, bool):
            frozen = frozen_raw
        else:
            raise CapsuleExtractionError(
                f"capsule at ETL index {etl_index} has non-boolean ledger.frozen"
            )

        row = {
            "claim_id": claim_id,
            "ended_at": int(record.get("ended_at", etl_index)),
            "arm_id": record.get("trial_arm_id"),
            "intervention_id": record.get("trial_intervention_id"),
            "trial_nonce_b64": _normalize_trial_nonce_b64(record.get("trial_nonce_hex"), etl_index),
            "k_bits_total": float(k_bits_total),
            "frozen_event": 1 if frozen else 0,
            "censored": 0 if frozen else 1,
            "lane": record.get("lane") or record.get("eprocess_kind") or "unknown",
            "adversary_type": record.get("adversary_type"),
            "holdout_ref": record.get("holdout_ref"),
            "holdout_handle": record.get("holdout_handle_hash_hex"),
            "topic_id": topic_id,
            "nullspec_id": record.get("nullspec_id_hex"),
            "outcome": _settlement_outcome(record, frozen),
        }
        rows.append(row)
    return rows


def read_extracted_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        for row in rows:
            row["k_bits_total"] = float(row["k_bits_total"])
            row["frozen_event"] = int(row["frozen_event"])
            row["censored"] = int(row["censored"])
            row["arm_id"] = int(row["arm_id"]) if row["arm_id"] not in ("", None) else None
            row["ended_at"] = int(row["ended_at"]) if row["ended_at"] not in ("", None) else None
            for key in ("intervention_id", "trial_nonce_b64", "lane", "adversary_type", "holdout_ref", "holdout_handle", "topic_id", "nullspec_id", "outcome"):
                if row.get(key) == "":
                    row[key] = None
        return rows

    if path.suffix.lower() == ".parquet":
        try:
            import pandas as pd
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "Reading parquet requires pandas. Install with `python -m pip install -e '.[analysis]'`."
            ) from exc
        return pd.read_parquet(path).to_dict(orient="records")

    raise ValueError("Unsupported extracted dataset format; use .csv or .parquet")


def write_extracted_rows(rows: list[dict[str, Any]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.suffix.lower() == ".csv":
        with out_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=_REQUIRED_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
        return

    if out_path.suffix.lower() == ".parquet":
        try:
            import pandas as pd
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "Writing parquet requires pandas. Install with `python -m pip install -e '.[analysis]'`."
            ) from exc
        pd.DataFrame(rows, columns=_REQUIRED_COLUMNS).to_parquet(out_path, index=False)
        return

    raise ValueError("Unsupported output format; use .csv or .parquet")


def run_extraction(etl_path: Path, out_path: Path) -> list[dict[str, Any]]:
    records = parse_json_records(read_etl_records(etl_path))
    rows = extract_capsule_rows(records)
    write_extracted_rows(rows, out_path)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract trial rows from ClaimCapsule ETL records")
    parser.add_argument("--etl", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path, help="Output file (.csv or .parquet)")
    args = parser.parse_args()

    rows = run_extraction(args.etl, args.out)
    if not rows:
        raise SystemExit("No claim capsules found in ETL")
    print(f"Extracted {len(rows)} capsule rows to {args.out}")


if __name__ == "__main__":
    main()
