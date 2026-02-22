from __future__ import annotations

import argparse
from pathlib import Path

from analysis.epistemic_trial.report import generate_report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deprecated wrapper. Use analysis.epistemic_trial.report as the canonical pipeline."
    )
    parser.add_argument("--etl", required=True, type=Path, help="Path to ETL log")
    parser.add_argument("--out", required=True, type=Path, help="Output directory for analysis artifacts")
    args = parser.parse_args()
    generate_report(args.etl, args.out)


if __name__ == "__main__":
    main()
