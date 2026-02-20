#!/usr/bin/env python3
"""Bit-flip label exfiltration against baseline and EvidenceOS-style oracle controls."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from dataclasses import dataclass
from typing import Dict, List, Tuple


def generate_labels(n: int, seed: int) -> List[int]:
    rng = random.Random(seed)
    return [rng.randint(0, 1) for _ in range(n)]


@dataclass
class BaselineOracle:
    labels: List[int]

    def query(self, prediction: List[int]) -> Dict[str, object]:
        if len(prediction) != len(self.labels):
            raise ValueError("prediction vector length mismatch")
        matches = sum(int(p == y) for p, y in zip(prediction, self.labels))
        return {
            "accuracy": matches / len(self.labels),
            "query_index": None,
            "status": "ok",
        }


@dataclass
class EvidenceOSMockOracle:
    labels: List[int]
    quantization_step: float = 0.10
    hysteresis_margin: float = 0.07
    max_queries: int = 32

    def __post_init__(self) -> None:
        self.query_count = 0
        self._last_reported = None

    def _receipt(self, prediction: List[int], status: str, output: float | None) -> Dict[str, object]:
        raw = json.dumps(
            {
                "query_index": self.query_count,
                "prediction_hash": hashlib.sha256(bytes(prediction)).hexdigest(),
                "status": status,
                "output": output,
            },
            sort_keys=True,
        )
        capsule = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return {
            "query_index": self.query_count,
            "status": status,
            "capsule_receipt": capsule,
            "accuracy": output,
        }

    def query(self, prediction: List[int]) -> Dict[str, object]:
        if len(prediction) != len(self.labels):
            raise ValueError("prediction vector length mismatch")

        self.query_count += 1
        if self.query_count > self.max_queries:
            return self._receipt(prediction, "budget_exhausted", None)

        matches = sum(int(p == y) for p, y in zip(prediction, self.labels))
        raw_accuracy = matches / len(self.labels)
        quantized = round(raw_accuracy / self.quantization_step) * self.quantization_step

        if self._last_reported is None:
            self._last_reported = quantized
        elif abs(quantized - self._last_reported) < self.hysteresis_margin:
            quantized = self._last_reported
        else:
            self._last_reported = quantized

        return self._receipt(prediction, "ok", quantized)


def bitflip_attack(oracle: object, n: int) -> Tuple[List[int], int]:
    guess = [0] * n
    baseline = oracle.query(guess)["accuracy"]
    queries = 1

    for idx in range(n):
        candidate = guess.copy()
        candidate[idx] = 1
        response = oracle.query(candidate)
        queries += 1
        observed = response.get("accuracy")

        if response.get("status") != "ok" or observed is None or baseline is None:
            break

        if observed > baseline:
            guess[idx] = 1
            baseline = observed
        elif observed < baseline:
            guess[idx] = 0
            baseline = observed
        else:
            guess[idx] = 0

    return guess, queries


def recovered_accuracy(recovered: List[int], truth: List[int]) -> float:
    return sum(int(a == b) for a, b in zip(recovered, truth)) / len(truth)


def run(mode: str, n: int, seed: int) -> Dict[str, object]:
    labels = generate_labels(n, seed)
    oracle: object
    if mode == "baseline":
        oracle = BaselineOracle(labels)
    elif mode == "evidenceos-mock":
        oracle = EvidenceOSMockOracle(labels)
    else:
        raise ValueError(f"unknown mode: {mode}")

    recovered, queries = bitflip_attack(oracle, n)
    return {
        "mode": mode,
        "n": n,
        "seed": seed,
        "queries": queries,
        "recovered_accuracy": recovered_accuracy(recovered, labels),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["baseline", "evidenceos-mock"], default="baseline")
    parser.add_argument("--n", type=int, default=64)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    result = run(args.mode, args.n, args.seed)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
