#!/usr/bin/env python3
"""Naive accuracy oracle used for label-exfiltration demos."""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from typing import List


@dataclass
class BaselineOracle:
    """Returns exact accuracy for a binary prediction vector."""

    labels: List[int]

    def score(self, prediction: List[int]) -> float:
        if len(prediction) != len(self.labels):
            raise ValueError("prediction vector length mismatch")
        matches = sum(int(p == y) for p, y in zip(prediction, self.labels))
        return matches / len(self.labels)


def generate_labels(n: int, seed: int) -> List[int]:
    rng = random.Random(seed)
    return [rng.randint(0, 1) for _ in range(n)]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=64, help="Label vector size")
    parser.add_argument("--seed", type=int, default=7, help="Deterministic seed")
    parser.add_argument(
        "--prediction-json",
        type=str,
        default=None,
        help="Optional prediction vector as a JSON list",
    )
    args = parser.parse_args()

    labels = generate_labels(args.n, args.seed)
    oracle = BaselineOracle(labels)

    if args.prediction_json is None:
        prediction = [0] * args.n
    else:
        prediction = json.loads(args.prediction_json)

    score = oracle.score(prediction)
    payload = {
        "n": args.n,
        "seed": args.seed,
        "accuracy": score,
    }
    print(json.dumps(payload))


if __name__ == "__main__":
    main()
