from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Optional

MAX_MULTIPLIER: float = 1e6


def validate_prior(prior: float) -> float:
    if not math.isfinite(prior):
        raise ValueError("prior must be finite")
    if prior <= 0.0 or prior > 1.0:
        raise ValueError("prior must be in (0, 1]")
    return prior


def normalize_prior(prior: Optional[float]) -> float:
    if prior is None:
        return 1.0
    return validate_prior(prior)


def prior_multiplier(prior: float) -> float:
    prior = validate_prior(prior)
    multiplier = 1.0 / prior
    if multiplier < 1.0:
        return 1.0
    if multiplier > MAX_MULTIPLIER:
        return MAX_MULTIPLIER
    return multiplier


@dataclass(frozen=True)
class PriorThreshold:
    prior: float
    multiplier: float
    effective_threshold: float


def compute_prior_threshold(alpha: float, prior: Optional[float]) -> PriorThreshold:
    normalized_prior = normalize_prior(prior)
    multiplier = prior_multiplier(normalized_prior)
    effective_threshold = (1.0 / alpha) * multiplier
    return PriorThreshold(
        prior=normalized_prior,
        multiplier=multiplier,
        effective_threshold=effective_threshold,
    )
