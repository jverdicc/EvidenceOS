#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    raw = out_dir / "raw" / "results.json"
    fig_dir = out_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    with raw.open("r", encoding="utf-8") as fh:
        results = json.load(fh)

    metrics = results["metrics"]

    table_rows = [
        ("Scenario tests (total)", metrics["scenario_total"]),
        ("Scenario tests (passed)", metrics["scenario_passed"]),
        ("Scenario tests (failed)", metrics["scenario_failed"]),
        ("Probe detector throttled", str(metrics["probe_saw_throttle"]).lower()),
        ("Probe detector froze", str(metrics["probe_saw_freeze"]).lower()),
    ]

    with (fig_dir / "table_1.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["result", "value"])
        writer.writerows(table_rows)

    lines = ["# FORC10 Reproduction Table", "", "| Result | Value |", "|---|---:|"]
    for label, value in table_rows:
        lines.append(f"| {label} | {value} |")
    (fig_dir / "table_1.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
