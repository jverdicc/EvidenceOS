from evidenceos.judge.judge import Judge, JudgePolicy
from evidenceos.ledger.ledger import ConservationLedger

def test_judge_supported_when_evalue_pass() -> None:
    j = Judge(JudgePolicy(alpha=0.05))
    l = ConservationLedger()
    out = j.evaluate(l, e_value=30.0)
    assert out.status == "Supported"

def test_judge_rejected_when_evalue_fail() -> None:
    j = Judge(JudgePolicy(alpha=0.05))
    l = ConservationLedger()
    out = j.evaluate(l, e_value=2.0)
    assert out.status == "Rejected"

def test_judge_inconclusive_dp_limited() -> None:
    j = Judge(JudgePolicy(alpha=0.05, dp_significance_buffer=0.1))
    l = ConservationLedger()
    out = j.evaluate(l, e_value=30.0, improvement=0.05, dp_noise_floor=0.0)
    assert out.status == "Inconclusive_DP_Limited"
