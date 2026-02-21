#!/usr/bin/env python3
import argparse
import csv
import json
import os
import subprocess
from pathlib import Path


def run(cmd, cwd: Path, env=None):
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    subprocess.run(cmd, cwd=cwd, check=True, env=merged_env)


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    out_dir = Path(args.out_dir).resolve()
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    run(
        [
            "cargo",
            "test",
            "-p",
            "evidenceos-daemon",
            "--test",
            "scenarios_system",
            "--",
            "--nocapture",
        ],
        cwd=repo_root,
    )
    run(
        [
            "cargo",
            "test",
            "-p",
            "evidenceos-daemon",
            "--test",
            "probing_detection_system",
            "--",
            "--nocapture",
        ],
        cwd=repo_root,
    )

    scenarios_summary = load_json(repo_root / "artifacts" / "scenarios" / "summary.json")
    probing_summary = load_json(
        repo_root / "artifacts" / "probing" / "probing_detection_system.json"
    )

    rustc_version = subprocess.check_output(["rustc", "--version"], text=True).strip()

    results = {
        "metadata": {
            "harness": "forc10",
            "rustc_version": rustc_version,
            "inputs": {
                "scenarios": "artifacts/scenarios/summary.json",
                "probing": "artifacts/probing/probing_detection_system.json",
            },
        },
        "metrics": {
            "scenario_total": int(scenarios_summary["totals"]["total"]),
            "scenario_passed": int(scenarios_summary["totals"]["passed"]),
            "scenario_failed": int(scenarios_summary["totals"]["failed"]),
            "probe_saw_throttle": bool(probing_summary["saw_throttle"]),
            "probe_saw_freeze": bool(probing_summary["saw_freeze"]),
        },
    }

    with (raw_dir / "results.json").open("w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, sort_keys=True)
        fh.write("\n")

    with (raw_dir / "results.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["metric", "value"])
        for key, value in sorted(results["metrics"].items()):
            writer.writerow([key, value])


if __name__ == "__main__":
    main()
