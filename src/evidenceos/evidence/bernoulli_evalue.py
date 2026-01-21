from __future__ import annotations

import math


def bernoulli_e_increment(x: int, p0: float, p1: float) -> float:
    if x not in (0, 1):
        raise ValueError("x must be 0 or 1")
    if not (math.isfinite(p0) and math.isfinite(p1)):
        raise ValueError("p0 and p1 must be finite")
    if not (0.0 <= p1 < p0 < 1.0):
        raise ValueError("require 0 <= p1 < p0 < 1")
    if x == 1:
        return p1 / p0
    return (1.0 - p1) / (1.0 - p0)
