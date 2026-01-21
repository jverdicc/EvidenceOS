from __future__ import annotations

from dataclasses import dataclass
import math

from evidenceos.evidence.priors import compute_prior_threshold


@dataclass
class EWLState:
    wealth: float
    alpha: float
    threshold: float
    bankruptcy_epsilon: float
    prior: float
    prior_multiplier: float

    @classmethod
    def from_inputs(
        cls,
        *,
        alpha: float,
        prior: float | None,
        wealth: float = 1.0,
        bankruptcy_epsilon: float = 1e-6,
    ) -> "EWLState":
        threshold = compute_prior_threshold(alpha=alpha, prior=prior)
        return cls(
            wealth=wealth,
            alpha=alpha,
            threshold=threshold.effective_threshold,
            bankruptcy_epsilon=bankruptcy_epsilon,
            prior=threshold.prior,
            prior_multiplier=threshold.multiplier,
        )

    def apply_e_increment(self, e: float) -> None:
        if not math.isfinite(e):
            raise ValueError("e increment must be finite")
        if e <= 0.0:
            raise ValueError("e increment must be positive")
        self.wealth *= e

    def status(self) -> str:
        if self.wealth >= self.threshold:
            return "SUPPORTED+"
        if self.wealth < self.bankruptcy_epsilon:
            return "BANKRUPT"
        return "INCONCLUSIVE"
