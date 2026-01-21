from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from evidenceos.ledger.ledger import ConservationLedger


@dataclass(frozen=True)
class MultiFidelityPolicy:
    proxy_threshold: float
    stage_a_cost: float = 0.0  # evidence charge
    stage_c_cost: float = 0.0  # evidence charge


class MultiFidelityOracle:
    """Multi-fidelity gate: cheap proxy score first; only then expensive oracle."""

    def __init__(self, policy: MultiFidelityPolicy, expensive_oracle: Callable[[ConservationLedger], float]):
        self.policy = policy
        self.expensive_oracle = expensive_oracle

    def evaluate(self, ledger: ConservationLedger, proxy_score: float) -> Optional[float]:
        ledger.adaptivity.charge_query(1)
        if self.policy.stage_a_cost:
            ledger.evidence.charge(self.policy.stage_a_cost)

        if proxy_score < self.policy.proxy_threshold:
            return None

        if self.policy.stage_c_cost:
            ledger.evidence.charge(self.policy.stage_c_cost)
        return self.expensive_oracle(ledger)
