"""NullSpec arm comparison with Bonferroni correction."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from statistics import median


def read_rows(path: Path):
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("kind") != "ClaimSettlementEvent":
                continue
            if rec.get("intervention_id") is None:
                continue
            rows.append(rec)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--etl", required=True, type=Path)
    parser.add_argument("--alpha", type=float, default=0.05)
    parser.add_argument("--median-k-threshold", type=float, default=8.0)
    args = parser.parse_args()

    rows = read_rows(args.etl)
    by_arm = defaultdict(list)
    for r in rows:
        by_arm[r["intervention_id"]].append(r)

    arms = sorted(by_arm)[:5]
    if not arms:
        print("No eligible trial arms found.")
        return

    adjusted_alpha = args.alpha / len(arms)
    print(f"Bonferroni-adjusted alpha: {adjusted_alpha:.6f}")

    for arm in arms:
        sample = by_arm[arm]
        frozen = [r for r in sample if r.get("outcome") == "FROZEN"]
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
