import pytest

from evidenceos.ledger.ledger import ConservationLedger, EvidenceWealthLedger, LedgerViolation


def test_ewl_bankruptcy_gates() -> None:
    ledger = EvidenceWealthLedger(wealth=1.0, bankruptcy_threshold=0.5)
    with pytest.raises(LedgerViolation):
        ledger.apply_e_value(0.4)


def test_ledger_fail_closed_on_bankruptcy() -> None:
    ledger = ConservationLedger()
    ledger.wealth.wealth = 0.1
    ledger.wealth.bankruptcy_threshold = 0.5
    with pytest.raises(LedgerViolation):
        ledger.fail_closed_if_corrupted()
