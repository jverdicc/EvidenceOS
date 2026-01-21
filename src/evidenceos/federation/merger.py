from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from .types import GlobalLedger, IntegrityState, LocalLedgerSummary, MergerPolicy

@dataclass(frozen=True)
class MergeInputs:
    local_ledgers: Tuple[LocalLedgerSummary, ...]
    local_evalues: Tuple[float, ...]
    weights: Tuple[float, ...]
    epsilons: Tuple[Optional[float], ...]
    deltas: Tuple[Optional[float], ...]


class Merger:
    def __init__(self, policy: MergerPolicy):
        self.policy = policy

    def merge_integrity(self, states: List[IntegrityState]) -> IntegrityState:
        if self.policy.integrity_merge == "any_corrupted_invalid":
            if any(s == "Corrupted" for s in states):
                return "Corrupted"
            if any(s == "Unknown" for s in states):
                return "Unknown"
            return "Trusted"

        corrupted = sum(1 for s in states if s == "Corrupted")
        if corrupted > len(states) // 2:
            return "Corrupted"
        if any(s == "Unknown" for s in states):
            return "Unknown"
        return "Trusted"

    def merge_evalues(self, evalues: List[float], weights: List[float]) -> float:
        if self.policy.evidence_merge == "weighted_mean_evalues":
            s = sum(weights)
            if s <= 0:
                raise ValueError("weights must sum to >0")
            return sum((w / s) * e for w, e in zip(weights, evalues))

        if not self.policy.certificates.independence_certified:
            raise ValueError("product_evalues requires independence_certified")
        prod = 1.0
        for e in evalues:
            prod *= e
        return prod

    def merge_dp(self, eps: List[Optional[float]], dls: List[Optional[float]]) -> Tuple[Optional[float], Optional[float]]:
        if all(e is None for e in eps) and all(d is None for d in dls):
            return None, None
        e2 = [e for e in eps if e is not None]
        d2 = [d for d in dls if d is not None]
        if not e2:
            return None, None

        if self.policy.dp_merge == "max_if_disjoint_else_sum":
            if self.policy.certificates.identity_disjointness_certified:
                return max(e2), (max(d2) if d2 else None)
            return sum(e2), (sum(d2) if d2 else None)
        if self.policy.dp_merge == "max":
            return max(e2), (max(d2) if d2 else None)
        return sum(e2), (sum(d2) if d2 else None)

    def merge_global(self, inputs: MergeInputs) -> GlobalLedger:
        integrity = self.merge_integrity([l.integrity_state for l in inputs.local_ledgers])
        violations: List[str] = []
        if integrity == "Corrupted":
            violations.append("integrity_corrupted")

        e_global = self.merge_evalues(list(inputs.local_evalues), list(inputs.weights)) if inputs.local_evalues else None
        eps_g, del_g = self.merge_dp(list(inputs.epsilons), list(inputs.deltas))

        return GlobalLedger(
            integrity_state=integrity,
            e_value_global=e_global,
            epsilon_global=eps_g,
            delta_global=del_g,
            violations=tuple(violations),
        )
