import pytest
from evidenceos.ledger.ledger import ConservationLedger, LedgerViolation

def test_ledger_monotone_and_limits() -> None:
    l = ConservationLedger()
    l.evidence.e_wealth_max = 1.0
    l.evidence.charge(0.4)
    l.evidence.charge(0.6)
    assert l.evidence.e_wealth_spent == pytest.approx(1.0)
    with pytest.raises(LedgerViolation):
        l.evidence.charge(0.1)

def test_integrity_fail_closed() -> None:
    l = ConservationLedger()
    l.integrity.mark_corrupted("canary_fail")
    with pytest.raises(LedgerViolation):
        l.fail_closed_if_corrupted()
