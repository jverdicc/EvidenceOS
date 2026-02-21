"""Kaplan-Meier survival analysis for EvidenceOS epistemic trial ETL output."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
from lifelines import KaplanMeierFitter


def read_settlements(path: Path):
    excluded = 0
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("kind") != "ClaimSettlementEvent":
                continue
            intervention_id = rec.get("intervention_id")
            outcome = rec.get("outcome")
            k_bits_total = rec.get("k_bits_total")
            if intervention_id is None or outcome is None or k_bits_total is None:
                excluded += 1
                continue
            rows.append(
                {
                    "arm": intervention_id,
                    "duration": float(k_bits_total),
                    "event": 1 if outcome == "FROZEN" else 0,
                }
            )
    return rows, excluded


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--etl", required=True, type=Path)
    parser.add_argument("--png", required=True, type=Path)
    parser.add_argument("--csv", required=True, type=Path)
    args = parser.parse_args()

    rows, excluded = read_settlements(args.etl)
    by_arm = defaultdict(list)
    for row in rows:
        by_arm[row["arm"]].append(row)

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
            f"censored={consort[(arm,'censored')]}, excluded={excluded}"
        )


if __name__ == "__main__":
    main()
