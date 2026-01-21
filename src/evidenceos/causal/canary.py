from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from random import Random
from typing import Protocol

DataBatch = dict[str, list[float]]


class HypothesisEvaluator(Protocol):
    def evaluate(self, data_batch: DataBatch) -> float:
        ...


@dataclass(frozen=True)
class Transform:
    name: str
    apply: Callable[[DataBatch], DataBatch]


@dataclass(frozen=True)
class TransformResult:
    name: str
    score: float
    delta: float
    fragile: bool


@dataclass(frozen=True)
class InvarianceResult:
    base_score: float
    transforms: tuple[TransformResult, ...]
    flag: str | None


def _validate_data_batch(data_batch: DataBatch) -> None:
    if not data_batch:
        raise ValueError("data_batch_empty")
    lengths = {len(values) for values in data_batch.values()}
    if len(lengths) != 1:
        raise ValueError("data_batch_length_mismatch")
    if 0 in lengths:
        raise ValueError("data_batch_empty_series")


def _copy_data_batch(data_batch: DataBatch) -> DataBatch:
    return {key: list(values) for key, values in data_batch.items()}


def shuffle(var: str) -> Transform:
    def _apply(data_batch: DataBatch) -> DataBatch:
        _validate_data_batch(data_batch)
        if var not in data_batch:
            raise ValueError(f"missing_variable:{var}")
        rng = Random(0)
        shuffled = list(data_batch[var])
        rng.shuffle(shuffled)
        transformed = _copy_data_batch(data_batch)
        transformed[var] = shuffled
        return transformed

    return Transform(name=f"shuffle({var})", apply=_apply)


def add_noise(var: str, sigma: float, seed: int) -> Transform:
    if sigma < 0:
        raise ValueError("sigma_negative")

    def _apply(data_batch: DataBatch) -> DataBatch:
        _validate_data_batch(data_batch)
        if var not in data_batch:
            raise ValueError(f"missing_variable:{var}")
        rng = Random(seed)
        transformed = _copy_data_batch(data_batch)
        transformed[var] = [value + rng.gauss(0.0, sigma) for value in data_batch[var]]
        return transformed

    return Transform(name=f"add_noise({var},sigma={sigma},seed={seed})", apply=_apply)


def rescale(var: str, factor: float) -> Transform:
    def _apply(data_batch: DataBatch) -> DataBatch:
        _validate_data_batch(data_batch)
        if var not in data_batch:
            raise ValueError(f"missing_variable:{var}")
        transformed = _copy_data_batch(data_batch)
        transformed[var] = [value * factor for value in data_batch[var]]
        return transformed

    return Transform(name=f"rescale({var},factor={factor})", apply=_apply)


def invariance_test(
    evaluator: HypothesisEvaluator,
    data: DataBatch,
    transforms: list[Transform],
    tolerance: float,
) -> InvarianceResult:
    if tolerance < 0:
        raise ValueError("tolerance_negative")
    _validate_data_batch(data)
    base_score = evaluator.evaluate(data)
    results: list[TransformResult] = []
    fragile_names: list[str] = []
    for transform in transforms:
        transformed_data = transform.apply(data)
        _validate_data_batch(transformed_data)
        score = evaluator.evaluate(transformed_data)
        delta = abs(base_score - score)
        fragile = delta > tolerance
        if fragile:
            fragile_names.append(transform.name)
        results.append(
            TransformResult(name=transform.name, score=score, delta=delta, fragile=fragile)
        )
    flag = "E_CAUSAL_FRAGILITY" if fragile_names else None
    return InvarianceResult(base_score=base_score, transforms=tuple(results), flag=flag)
