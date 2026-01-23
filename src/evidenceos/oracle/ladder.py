from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from evidenceos.ledger.ledger import ConservationLedger
from evidenceos.oracle.resolution import OracleResolution, QuantizedOracle, QuantizedOracleResult


@dataclass
class LadderState:
    best_score: Optional[float] = None


class LadderOracle:
    """Ladder-style oracle: only reveals an update if improvement >= eta.

    This is a coarse feedback channel to reduce leaderboard overfitting.
    """

    def __init__(
        self,
        *,
        eta: float,
        resolution: Optional[OracleResolution] = None,
        dataset_id: Optional[str] = None,
    ):
        if eta < 0:
            raise ValueError("eta must be >= 0")
        self.eta = eta
        self.state = LadderState()
        self._quantized: Optional[QuantizedOracle] = None
        if resolution is not None:
            if not dataset_id:
                raise ValueError("dataset_id required for quantized oracle")
            self._quantized = QuantizedOracle(resolution=resolution, dataset_id=dataset_id)

    def query(self, ledger: ConservationLedger, *, score: float) -> Tuple[float, float]:
        ledger.adaptivity.charge_query(1)
        # If no best yet, set best and reveal
        if self.state.best_score is None:
            self.state.best_score = score
            if self._quantized is None:
                return score, score
            quantized = self._quantized.query(
                ledger,
                score=score,
                local=False,
                charge_adaptivity=False,
            )
            return quantized.lower, quantized.upper
        best = self.state.best_score
        if score >= best + self.eta:
            self.state.best_score = score
            if self._quantized is None:
                return score, score
            quantized = self._quantized.query(
                ledger,
                score=score,
                local=True,
                charge_adaptivity=False,
            )
            return quantized.lower, quantized.upper
        # reveal old best
        if self._quantized is None:
            return best, best
        quantized = self._quantized.query(
            ledger,
            score=best,
            local=True,
            charge_adaptivity=False,
        )
        return quantized.lower, quantized.upper
