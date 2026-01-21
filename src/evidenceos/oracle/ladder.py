from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from evidenceos.ledger.ledger import ConservationLedger


@dataclass
class LadderState:
    best_score: Optional[float] = None


class LadderOracle:
    """Ladder-style oracle: only reveals an update if improvement >= eta.

    This is a coarse feedback channel to reduce leaderboard overfitting.
    """

    def __init__(self, *, eta: float):
        if eta < 0:
            raise ValueError("eta must be >= 0")
        self.eta = eta
        self.state = LadderState()

    def query(self, ledger: ConservationLedger, *, score: float) -> Tuple[float, float]:
        ledger.adaptivity.charge_query(1)
        # If no best yet, set best and reveal
        if self.state.best_score is None:
            self.state.best_score = score
            return score, score
        best = self.state.best_score
        if score >= best + self.eta:
            self.state.best_score = score
            return score, score
        # reveal old best
        return best, best
