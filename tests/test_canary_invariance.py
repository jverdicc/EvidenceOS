from __future__ import annotations

from dataclasses import dataclass
from math import sqrt

from evidenceos.causal.canary import (
    DataBatch,
    HypothesisEvaluator,
    invariance_test,
    rescale,
    shuffle,
)


def _mean(values: list[float]) -> float:
    return sum(values) / len(values)


def _correlation(values_x: list[float], values_y: list[float]) -> float:
    mean_x = _mean(values_x)
    mean_y = _mean(values_y)
    cov = sum((x - mean_x) * (y - mean_y) for x, y in zip(values_x, values_y, strict=True))
    var_x = sum((x - mean_x) ** 2 for x in values_x)
    var_y = sum((y - mean_y) ** 2 for y in values_y)
    if var_x == 0 or var_y == 0:
        raise ValueError("zero_variance")
    return cov / sqrt(var_x * var_y)


@dataclass(frozen=True)
class CorrelationEvaluator(HypothesisEvaluator):
    x_key: str
    y_key: str

    def evaluate(self, data_batch: DataBatch) -> float:
        return _correlation(data_batch[self.x_key], data_batch[self.y_key])


@dataclass(frozen=True)
class MeanEvaluator(HypothesisEvaluator):
    key: str

    def evaluate(self, data_batch: DataBatch) -> float:
        return _mean(data_batch[self.key])


def test_invariance_flags_fragility_for_shuffle() -> None:
    data: DataBatch = {
        "X": [1.0, 2.0, 3.0, 4.0, 5.0],
        "Y": [2.0, 4.0, 6.0, 8.0, 10.0],
    }
    evaluator = CorrelationEvaluator(x_key="X", y_key="Y")
    transforms = [rescale("X", 2.0), shuffle("X")]

    result = invariance_test(evaluator, data, transforms, tolerance=0.2)

    assert result.flag == "E_CAUSAL_FRAGILITY"
    assert result.transforms[0].fragile is False
    assert result.transforms[1].fragile is True


def test_invariance_passes_for_stable_mean() -> None:
    data: DataBatch = {
        "X": [1.0, 2.0, 3.0, 4.0, 5.0],
        "Y": [2.0, 4.0, 6.0, 8.0, 10.0],
    }
    evaluator = MeanEvaluator(key="Y")
    transforms = [rescale("X", 2.0), shuffle("X")]

    result = invariance_test(evaluator, data, transforms, tolerance=0.0)

    assert result.flag is None
    assert all(not transform.fragile for transform in result.transforms)
