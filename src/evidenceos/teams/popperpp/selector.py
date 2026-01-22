from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from evidenceos.schemas.popperpp import SubHypothesis


@dataclass
class UniformSelector:
    def choose(self, candidates: Iterable[SubHypothesis]) -> SubHypothesis:
        candidates_list = sorted(candidates, key=lambda item: item.id)
        if not candidates_list:
            raise ValueError("no_candidates")
        return candidates_list[0]


@dataclass
class GreedyExpectedInfoSelector:
    def choose(self, candidates: Iterable[SubHypothesis]) -> SubHypothesis:
        candidates_list = list(candidates)
        if not candidates_list:
            raise ValueError("no_candidates")
        return max(
            candidates_list,
            key=lambda item: float(item.test_object.params.get("expected_info", 0.0)),
        )


@dataclass
class BanditUCBSelector:
    def choose(self, candidates: Iterable[SubHypothesis]) -> SubHypothesis:
        candidates_list = list(candidates)
        if not candidates_list:
            raise ValueError("no_candidates")
        return max(
            candidates_list,
            key=lambda item: float(item.test_object.params.get("ucb", 0.0)),
        )
