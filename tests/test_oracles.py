from evidenceos.ledger.ledger import ConservationLedger
from evidenceos.oracle.ladder import LadderOracle
from evidenceos.oracle.multifidelity import MultiFidelityOracle, MultiFidelityPolicy

def test_ladder_only_updates_with_eta() -> None:
    l = ConservationLedger()
    o = LadderOracle(eta=0.05)
    out1 = o.query(l, score=0.80)
    out2 = o.query(l, score=0.82)  # improvement 0.02 < eta
    out3 = o.query(l, score=0.86)  # improvement 0.06 >= eta
    assert out1[0] == 0.80
    assert out2[0] == 0.80
    assert out3[0] == 0.86

def test_multifidelity_gates_expensive() -> None:
    l = ConservationLedger()
    called = {"n": 0}
    def expensive(ledger: ConservationLedger) -> float:
        called["n"] += 1
        return 0.99
    mf = MultiFidelityOracle(MultiFidelityPolicy(proxy_threshold=0.9), expensive)
    assert mf.evaluate(l, proxy_score=0.5) is None
    assert called["n"] == 0
    assert mf.evaluate(l, proxy_score=0.95) == 0.99
    assert called["n"] == 1
