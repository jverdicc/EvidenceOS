#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
from pathlib import Path

from experiments.experiment01_scenarios import run as run_scenarios
from experiments.experiment02_probing import run as run_probing
from figures.figure01_table1 import render
from kernel.io_schema import dump_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run FORC10 paper artifacts with deterministic settings.')
    parser.add_argument('--repo-root', required=True)
    parser.add_argument('--out-dir', required=True)
    parser.add_argument('--fixed-seed', type=int, default=20250311)
    parser.add_argument('--quick', action='store_true', help='Use pre-generated raw artifacts only (CI lightweight drift check).')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = Path(args.out_dir).resolve()

    if out_dir.exists():
        shutil.rmtree(out_dir)
    (out_dir / 'raw').mkdir(parents=True, exist_ok=True)

    rustc_version = subprocess.check_output(['rustc', '--version'], text=True).strip()

    metrics: dict[str, object] = {}
    metrics.update(run_scenarios(repo_root=repo_root, quick=args.quick))
    metrics.update(run_probing(repo_root=repo_root, quick=args.quick))

    results = {
        'schema_version': 'forc10.v1',
        'metadata': {
            'runner': 'artifacts/forc10/original_python/run_all.py',
            'quick_mode': bool(args.quick),
            'fixed_seed': int(args.fixed_seed),
            'rustc_version': rustc_version,
            'inputs': {
                'scenarios': 'artifacts/scenarios/summary.json',
                'probing': 'artifacts/probing/probing_detection_system.json',
            },
            'experiments': [
                'experiments/experiment01_scenarios.py',
                'experiments/experiment02_probing.py',
            ],
        },
        'metrics': metrics,
    }

    dump_json(out_dir / 'raw' / 'results.json', results)
    with (out_dir / 'raw' / 'results.csv').open('w', newline='', encoding='utf-8') as handle:
        writer = csv.writer(handle)
        writer.writerow(['metric', 'value'])
        for key, value in sorted(metrics.items()):
            writer.writerow([key, value])

    render(out_dir=out_dir, metrics=metrics)


if __name__ == '__main__':
    main()
