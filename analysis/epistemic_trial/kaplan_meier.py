"""Kaplan-Meier survival analysis for EvidenceOS epistemic trial data."""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
from lifelines import KaplanMeierFitter

from analysis.epistemic_trial.extract_from_capsules import (
    read_extracted_rows,
    run_extraction,
)


def _load_rows(dataset: Path | None, etl: Path | None) -> list[dict[str, object]]:
    if dataset is not None:
        return read_extracted_rows(dataset)
    assert etl is not None
    return run_extraction(etl, etl.with_suffix(".capsules.csv"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, help="Extracted capsule dataset (.csv/.parquet)")
    parser.add_argument("--etl", type=Path, help="Raw ETL (used when --dataset is omitted)")
    parser.add_argument("--png", required=True, type=Path)
    parser.add_argument("--csv", required=True, type=Path)
    args = parser.parse_args()

    if args.dataset is None and args.etl is None:
        raise SystemExit("Provide --dataset or --etl")

    rows = _load_rows(args.dataset, args.etl)
    by_arm = defaultdict(list)
    for row in rows:
        arm = row.get("intervention_id") or row.get("arm_id") or "unassigned"
        by_arm[str(arm)].append(
            {
                "duration": float(row["k_bits_total"]),
                "event": int(row["frozen_event"]),
            }
        )

    plt.figure(figsize=(8, 5))
    csv_rows = []
    consort = Counter()

    for arm, arm_rows in sorted(by_arm.items()):
        kmf = KaplanMeierFitter(label=arm)
        durations = [r["duration"] for r in arm_rows]
        events = [r["event"] for r in arm_rows]
        kmf.fit(durations=durations, event_observed=events)
        kmf.plot_survival_function(ci_show=True)
        consort[(arm, "assigned")] = len(arm_rows)
        consort[(arm, "frozen")] = sum(events)
        consort[(arm, "censored")] = len(arm_rows) - sum(events)

        surv = kmf.survival_function_.reset_index()
        for _, rec in surv.iterrows():
            csv_rows.append(
                {
                    "arm": arm,
                    "timeline": float(rec["timeline"]),
                    "survival": float(rec[arm]),
                }
            )

    args.png.parent.mkdir(parents=True, exist_ok=True)
    args.csv.parent.mkdir(parents=True, exist_ok=True)

    plt.title("Epistemic Trial Kaplan-Meier Survival")
    plt.xlabel("Cumulative k_bits")
    plt.ylabel("Survival probability")
    plt.grid(True, alpha=0.2)
    plt.tight_layout()
    plt.savefig(args.png, dpi=180)

    with args.csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["arm", "timeline", "survival"])
        writer.writeheader()
        writer.writerows(csv_rows)

    print("CONSORT flow counts:")
    for arm in sorted(by_arm):
        print(
            f"- {arm}: assigned={consort[(arm,'assigned')]}, "
            f"frozen={consort[(arm,'frozen')]}, "
            f"censored={consort[(arm,'censored')]}"
        )


if __name__ == "__main__":
    main()
