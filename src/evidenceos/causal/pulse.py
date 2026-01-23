from __future__ import annotations

from dataclasses import dataclass
from random import Random


@dataclass(frozen=True)
class CanaryPulsePolicy:
    every_n_settlements: int
    probability: float
    seed: int = 0
    require_on_first: bool = True

    def __post_init__(self) -> None:
        if self.every_n_settlements < 0:
            raise ValueError("every_n_settlements must be >= 0")
        if not (0.0 <= self.probability <= 1.0):
            raise ValueError("probability must be in [0,1]")


@dataclass
class CanaryPulseState:
    total_settlements: int = 0
    settlements_since_pulse: int = 0


def should_run_pulse(state: CanaryPulseState, policy: CanaryPulsePolicy) -> bool:
    if policy.require_on_first and state.total_settlements == 0:
        return True
    if policy.every_n_settlements and state.settlements_since_pulse >= policy.every_n_settlements:
        return True
    if policy.probability <= 0:
        return False
    rng = Random(policy.seed + state.total_settlements)
    return rng.random() < policy.probability


def record_settlement(state: CanaryPulseState, ran_pulse: bool) -> None:
    state.total_settlements += 1
    if ran_pulse:
        state.settlements_since_pulse = 0
    else:
        state.settlements_since_pulse += 1
