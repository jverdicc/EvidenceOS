#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path


def load_csv(path: Path) -> list[list[str]]:
    with path.open('r', encoding='utf-8') as handle:
        return list(csv.reader(handle))


def compare_json(actual, expected, tol: float, path: str = 'root') -> list[str]:
    errors: list[str] = []

    if path.endswith('.rustc_version'):
        return errors

    if type(actual) is not type(expected):
        return [f'{path}: type mismatch {type(actual)} != {type(expected)}']

    if isinstance(actual, dict):
        if set(actual) != set(expected):
            return [f'{path}: key mismatch {sorted(actual)} != {sorted(expected)}']
        for key in sorted(actual):
            errors.extend(compare_json(actual[key], expected[key], tol, f'{path}.{key}'))
        return errors

    if isinstance(actual, list):
        if len(actual) != len(expected):
            return [f'{path}: len mismatch {len(actual)} != {len(expected)}']
        for idx, (actual_v, expected_v) in enumerate(zip(actual, expected)):
            errors.extend(compare_json(actual_v, expected_v, tol, f'{path}[{idx}]'))
        return errors

    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        if not math.isclose(float(actual), float(expected), rel_tol=tol, abs_tol=tol):
            return [f'{path}: numeric mismatch {actual} != {expected}']
        return []

    if actual != expected:
        return [f'{path}: mismatch {actual!r} != {expected!r}']
    return []


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--out-dir', required=True)
    parser.add_argument('--expected-dir', required=True)
    parser.add_argument('--tolerance', type=float, default=1e-9)
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    expected_dir = Path(args.expected_dir).resolve()

    checks = [
        (out_dir / 'raw' / 'results.json', expected_dir / 'results.json', 'json'),
        (out_dir / 'raw' / 'results.csv', expected_dir / 'results.csv', 'csv'),
        (out_dir / 'figures' / 'table_1.csv', expected_dir / 'table_1.csv', 'csv'),
        (out_dir / 'figures' / 'table_1.md', expected_dir / 'table_1.md', 'text'),
    ]

    failures: list[str] = []
    for actual_path, expected_path, mode in checks:
        if not actual_path.exists():
            failures.append(f'missing output: {actual_path}')
            continue
        if not expected_path.exists():
            failures.append(f'missing expected: {expected_path}')
            continue

        if mode == 'json':
            actual = json.loads(actual_path.read_text(encoding='utf-8'))
            expected = json.loads(expected_path.read_text(encoding='utf-8'))
            failures.extend(compare_json(actual, expected, args.tolerance, path=actual_path.name))
        elif mode == 'csv':
            if load_csv(actual_path) != load_csv(expected_path):
                failures.append(f'csv mismatch: {actual_path.name}')
        else:
            if actual_path.read_text(encoding='utf-8') != expected_path.read_text(encoding='utf-8'):
                failures.append(f'text mismatch: {actual_path.name}')

    if failures:
        for failure in failures:
            print(f'VERIFY_FAIL: {failure}')
        raise SystemExit(1)

    print('verify passed')


if __name__ == '__main__':
    main()
