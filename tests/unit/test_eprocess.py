import math

import pytest

from evidenceos.stats.eprocess import EProcess


def test_eprocess_multiplicative_log_space() -> None:
    process = EProcess(alpha=0.1)
    process.observe(2.0)
    process.observe(0.5)
    assert process.value() == pytest.approx(1.0)
    assert math.isfinite(process.value())


def test_eprocess_crossed_threshold() -> None:
    process = EProcess(alpha=0.5)
    process.observe(2.0)
    assert process.crossed() is True


def test_eprocess_serialization_roundtrip() -> None:
    process = EProcess(alpha=0.2)
    process.observe(1.5)
    payload = process.to_dict()
    restored = EProcess.from_dict(payload)
    assert restored.value() == pytest.approx(process.value())
