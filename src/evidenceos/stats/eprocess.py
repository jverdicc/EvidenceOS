from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class EProcess:
    alpha: float
    _log_value: float = 0.0

    def __post_init__(self) -> None:
        if not 0 < self.alpha < 1:
            raise ValueError("alpha must be in (0, 1)")

    def observe(self, e: float) -> None:
        if e <= 0 or not math.isfinite(e):
            raise ValueError("e must be finite and > 0")
        self._log_value += math.log(e)

    def value(self) -> float:
        return math.exp(self._log_value)

    def crossed(self) -> bool:
        return self._log_value >= math.log(1 / self.alpha)

    def remaining_margin(self) -> float:
        threshold = math.log(1 / self.alpha)
        return max(0.0, threshold - self._log_value)

    def to_dict(self) -> dict:
        return {"alpha": self.alpha, "log_value": self._log_value}

    @classmethod
    def from_dict(cls, payload: dict) -> "EProcess":
        if "alpha" not in payload or "log_value" not in payload:
            raise ValueError("missing_fields")
        obj = cls(alpha=payload["alpha"])
        obj._log_value = float(payload["log_value"])
        return obj
