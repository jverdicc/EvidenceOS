import pytest

from evidenceos.judge.judge import Judge, JudgePolicy
from evidenceos.ledger.ledger import ConservationLedger


def test_prior_one_matches_base_threshold() -> None:
    judge = Judge(JudgePolicy(alpha=0.05))
    ledger = ConservationLedger()
    out = judge.evaluate(ledger, e_value=20.0, prior=1.0)
    assert out.status == "Supported"
    assert out.effective_threshold == pytest.approx(20.0)


def test_prior_low_tightens_threshold() -> None:
    judge = Judge(JudgePolicy(alpha=0.05))
    ledger = ConservationLedger()
    out = judge.evaluate(ledger, e_value=20.0, prior=0.1)
    assert out.status == "Rejected"
    assert out.effective_threshold == pytest.approx(200.0)


def test_prior_invalid_raises() -> None:
    judge = Judge(JudgePolicy(alpha=0.05))
    ledger = ConservationLedger()
    with pytest.raises(ValueError):
        judge.evaluate(ledger, e_value=20.0, prior=0.0)
    with pytest.raises(ValueError):
        judge.evaluate(ledger, e_value=20.0, prior=1.5)
