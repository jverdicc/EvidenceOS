"""NullSpec arm comparison with Bonferroni correction."""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from statistics import median

from analysis.epistemic_trial.extract_from_capsules import read_extracted_rows, run_extraction


def _load_rows(dataset: Path | None, etl: Path | None) -> list[dict[str, object]]:
    if dataset is not None:
        return read_extracted_rows(dataset)
    assert etl is not None
    return run_extraction(etl, etl.with_suffix(".capsules.csv"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, help="Extracted capsule dataset (.csv/.parquet)")
    parser.add_argument("--etl", type=Path, help="Raw ETL (used when --dataset is omitted)")
    parser.add_argument("--alpha", type=float, default=0.05)
    parser.add_argument("--median-k-threshold", type=float, default=8.0)
    args = parser.parse_args()

    if args.dataset is None and args.etl is None:
        raise SystemExit("Provide --dataset or --etl")

    rows = _load_rows(args.dataset, args.etl)
    by_arm = defaultdict(list)
    for r in rows:
        arm = r.get("intervention_id")
        if arm is None:
            continue
        by_arm[str(arm)].append(r)

    arms = sorted(by_arm)[:5]
    if not arms:
        print("No eligible trial arms found.")
        return

    adjusted_alpha = args.alpha / len(arms)
    print(f"Bonferroni-adjusted alpha: {adjusted_alpha:.6f}")

    for arm in arms:
        sample = by_arm[arm]
        frozen = [r for r in sample if str(r.get("outcome")) == "FROZEN"]
        false_cert_rate = len(frozen) / len(sample)
        median_k = median(float(r.get("k_bits_total", 0.0)) for r in sample)

        loose = false_cert_rate > adjusted_alpha
        brittle = median_k < args.median_k_threshold
        verdict = []
        if loose:
            verdict.append("TOO_LOOSE")
        if brittle:
            verdict.append("TOO_BRITTLE")
        if not verdict:
            verdict.append("OK")

        print(
            f"{arm}: n={len(sample)}, false_cert_rate={false_cert_rate:.4f}, "
            f"median_k_to_frozen={median_k:.3f}, verdict={','.join(verdict)}"
        )


if __name__ == "__main__":
    main()
