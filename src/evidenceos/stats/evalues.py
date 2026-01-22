from __future__ import annotations

import math


def p_to_e_calibrator(p: float, kappa: float) -> float:
    """
    POPPER p-to-e calibrator: e = kappa * p**(kappa-1), with kappa in (0,1).
    Guard p in (0,1], treat p==0 as eps.
    """
    if not 0 < kappa < 1:
        raise ValueError("kappa must be in (0, 1)")
    if p < 0 or p > 1:
        raise ValueError("p must be in [0, 1]")
    if p == 0:
        p = math.nextafter(0.0, 1.0)
    if p == 0:
        raise ValueError("p underflow")
    return kappa * (p ** (kappa - 1))
