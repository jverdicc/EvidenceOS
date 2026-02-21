#!/usr/bin/env python3
import argparse
import csv
import json
import math
from pathlib import Path


def load_csv(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        return list(csv.reader(fh))


def compare_json(actual, expected, tol, path="root"):
    errors = []
    if path.endswith(".rustc_version"):
        return errors
    if type(actual) is not type(expected):
        return [f"{path}: type mismatch {type(actual)} != {type(expected)}"]

    if isinstance(actual, dict):
        actual_keys = set(actual)
        expected_keys = set(expected)
        if actual_keys != expected_keys:
            errors.append(f"{path}: key mismatch {sorted(actual_keys)} != {sorted(expected_keys)}")
            return errors
        for key in sorted(actual_keys):
            errors.extend(compare_json(actual[key], expected[key], tol, f"{path}.{key}"))
        return errors

    if isinstance(actual, list):
        if len(actual) != len(expected):
            errors.append(f"{path}: len mismatch {len(actual)} != {len(expected)}")
            return errors
        for idx, (a_val, e_val) in enumerate(zip(actual, expected)):
            errors.extend(compare_json(a_val, e_val, tol, f"{path}[{idx}]"))
        return errors

    if isinstance(actual, (float, int)) and isinstance(expected, (float, int)):
        if not math.isclose(float(actual), float(expected), rel_tol=tol, abs_tol=tol):
            errors.append(f"{path}: numeric mismatch {actual} != {expected}")
        return errors

    if actual != expected:
        errors.append(f"{path}: mismatch {actual!r} != {expected!r}")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--golden-dir", required=True)
    parser.add_argument("--tolerance", type=float, default=1e-9)
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    golden_dir = Path(args.golden_dir).resolve()

    checks = [
        (out_dir / "raw" / "results.json", golden_dir / "results.json", "json"),
        (out_dir / "raw" / "results.csv", golden_dir / "results.csv", "csv"),
        (out_dir / "figures" / "table_1.csv", golden_dir / "table_1.csv", "csv"),
        (out_dir / "figures" / "table_1.md", golden_dir / "table_1.md", "text"),
    ]

    failures = []
    for actual_path, expected_path, kind in checks:
        if not actual_path.exists():
            failures.append(f"missing output: {actual_path}")
            continue
        if not expected_path.exists():
            failures.append(f"missing golden: {expected_path}")
            continue

        if kind == "json":
            actual = json.loads(actual_path.read_text(encoding="utf-8"))
            expected = json.loads(expected_path.read_text(encoding="utf-8"))
            failures.extend(compare_json(actual, expected, args.tolerance, path=actual_path.name))
        elif kind == "csv":
            if load_csv(actual_path) != load_csv(expected_path):
                failures.append(f"csv mismatch: {actual_path.name}")
        else:
            if actual_path.read_text(encoding="utf-8") != expected_path.read_text(encoding="utf-8"):
                failures.append(f"text mismatch: {actual_path.name}")

    if failures:
        for failure in failures:
            print(f"VERIFY_FAIL: {failure}")
        raise SystemExit(1)

    print("verify passed")


if __name__ == "__main__":
    main()
