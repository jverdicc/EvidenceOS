from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import Optional, Tuple


class LedgerViolation(RuntimeError):
    pass


@dataclass
class EvidenceWealthLedger:
    wealth: float = 1.0
    bankruptcy_threshold: float = 1e-12
    history: Tuple[float, ...] = ()

    def apply_e_value(self, e_value: float) -> float:
        if not math.isfinite(e_value) or e_value <= 0.0:
            raise LedgerViolation("e_value_invalid")
        next_wealth = self.wealth * e_value
        self.wealth = next_wealth
        self.history = self.history + (e_value,)
        if self.wealth < self.bankruptcy_threshold:
            raise LedgerViolation("ewl_bankrupt")
        return self.wealth

    def is_bankrupt(self) -> bool:
        return self.wealth < self.bankruptcy_threshold


@dataclass
class EvidenceLane:
    # e-wealth style budgeting; threshold is 1/alpha typically
    e_wealth_spent: float = 0.0
    e_wealth_max: Optional[float] = None

    def charge(self, amount: float) -> None:
        if amount < 0:
            raise ValueError("amount must be >= 0")
        self.e_wealth_spent += amount
        if self.e_wealth_max is not None and self.e_wealth_spent > self.e_wealth_max:
            raise LedgerViolation("evidence_budget_exceeded")


@dataclass
class AdaptivityLane:
    holdout_queries_used: int = 0
    holdout_queries_max: Optional[int] = None
    adaptive_rounds_used: int = 0
    adaptive_rounds_max: Optional[int] = None

    def charge_query(self, n: int = 1) -> None:
        if n < 0:
            raise ValueError("n must be >= 0")
        self.holdout_queries_used += n
        if self.holdout_queries_max is not None and self.holdout_queries_used > self.holdout_queries_max:
            raise LedgerViolation("holdout_query_budget_exceeded")

    def charge_round(self, n: int = 1) -> None:
        if n < 0:
            raise ValueError("n must be >= 0")
        self.adaptive_rounds_used += n
        if self.adaptive_rounds_max is not None and self.adaptive_rounds_used > self.adaptive_rounds_max:
            raise LedgerViolation("adaptive_round_budget_exceeded")


@dataclass
class PrivacyLane:
    enabled: bool = False
    epsilon_spent: float = 0.0
    delta_spent: float = 0.0
    epsilon_max: Optional[float] = None
    delta_max: Optional[float] = None

    def charge(self, epsilon: float, delta: float) -> None:
        if not self.enabled:
            raise LedgerViolation("privacy_not_enabled")
        if epsilon < 0 or delta < 0:
            raise ValueError("epsilon/delta must be >= 0")
        self.epsilon_spent += epsilon
        self.delta_spent += delta
        if self.epsilon_max is not None and self.epsilon_spent > self.epsilon_max:
            raise LedgerViolation("epsilon_budget_exceeded")
        if self.delta_max is not None and self.delta_spent > self.delta_max:
            raise LedgerViolation("delta_budget_exceeded")


@dataclass
class IntegrityLane:
    state: str = "Trusted"  # Trusted / Unknown / Corrupted
    flags: Tuple[str, ...] = ()

    def mark_corrupted(self, reason: str) -> None:
        self.state = "Corrupted"
        self.flags = tuple(sorted(set(self.flags + (reason,))))


@dataclass
class ConservationLedger:
    evidence: EvidenceLane = field(default_factory=EvidenceLane)
    adaptivity: AdaptivityLane = field(default_factory=AdaptivityLane)
    privacy: PrivacyLane = field(default_factory=PrivacyLane)
    integrity: IntegrityLane = field(default_factory=IntegrityLane)
    wealth: EvidenceWealthLedger = field(default_factory=EvidenceWealthLedger)

    def fail_closed_if_corrupted(self) -> None:
        if self.integrity.state == "Corrupted":
            raise LedgerViolation("integrity_corrupted:" + ",".join(self.integrity.flags))
        if self.wealth.is_bankrupt():
            raise LedgerViolation("ewl_bankrupt")
