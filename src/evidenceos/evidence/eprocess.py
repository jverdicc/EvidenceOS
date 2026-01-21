from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from evidenceos.evidence.priors import PriorThreshold, compute_prior_threshold


@dataclass(frozen=True)
class EProcessRecord:
    alpha: float
    prior: float
    prior_multiplier: float
    effective_threshold: float

    @classmethod
    def from_inputs(cls, alpha: float, prior: Optional[float]) -> "EProcessRecord":
        threshold = compute_prior_threshold(alpha=alpha, prior=prior)
        return cls(
            alpha=alpha,
            prior=threshold.prior,
            prior_multiplier=threshold.multiplier,
            effective_threshold=threshold.effective_threshold,
        )

    def to_dict(self) -> dict[str, float]:
        return {
            "alpha": self.alpha,
            "prior": self.prior,
            "prior_multiplier": self.prior_multiplier,
            "effective_threshold": self.effective_threshold,
        }

    def to_prior_threshold(self) -> PriorThreshold:
        return PriorThreshold(
            prior=self.prior,
            multiplier=self.prior_multiplier,
            effective_threshold=self.effective_threshold,
        )
