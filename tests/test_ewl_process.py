import pytest

from evidenceos.evidence.ewl import EWLState


def test_wealth_multiplies() -> None:
    state = EWLState.from_inputs(alpha=0.05, prior=None)
    state.apply_e_increment(2.0)
    state.apply_e_increment(0.5)
    assert state.wealth == pytest.approx(1.0)


def test_prior_increases_threshold() -> None:
    state = EWLState.from_inputs(alpha=0.05, prior=0.1)
    assert state.threshold == pytest.approx(200.0)
    assert state.prior_multiplier == pytest.approx(10.0)


def test_bankruptcy_triggers() -> None:
    state = EWLState.from_inputs(alpha=0.05, prior=None, bankruptcy_epsilon=1e-3)
    state.apply_e_increment(1e-4)
    assert state.status() == "BANKRUPT"
