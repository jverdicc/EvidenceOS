import math

import pytest

from evidenceos.stats.evalues import p_to_e_calibrator


def test_p_to_e_calibrator_basic() -> None:
    assert p_to_e_calibrator(1.0, 0.5) == pytest.approx(0.5)


def test_p_to_e_calibrator_small_p() -> None:
    value = p_to_e_calibrator(1e-12, 0.5)
    assert math.isfinite(value)
    assert value > 1.0


def test_p_to_e_calibrator_invalid_kappa() -> None:
    with pytest.raises(ValueError):
        p_to_e_calibrator(0.5, 1.0)


def test_p_to_e_calibrator_invalid_p() -> None:
    with pytest.raises(ValueError):
        p_to_e_calibrator(-0.1, 0.5)
