from typing import Dict

from evidenceos.ledger.ledger import ConservationLedger
from evidenceos.schemas.popperpp import FalsificationConfig
from evidenceos.teams.popperpp.team import PopperppTeam
from evidenceos.teams.popperpp.types import ClaimContract, DataContract


class ListExecutor:
    def __init__(self, p_values: list[float]) -> None:
        self.p_values = p_values
        self.idx = 0

    def execute(self, subhypothesis, lane: str, context: Dict[str, object]) -> float:
        del subhypothesis, lane, context
        value = self.p_values[self.idx]
        self.idx += 1
        return value


def test_popperpp_smoke() -> None:
    config = FalsificationConfig(
        alpha=0.05,
        kappa=0.5,
        max_rounds=3,
        max_failed_rounds=0,
        max_total_tests_per_claim=3,
        max_total_tests_per_dataset=10,
        lane_policy={"default": "CANARY"},
        selection_policy="uniform",
        allow_llm_design=False,
    )
    claim = ClaimContract(claim_id="claim-1", dataset_id="dataset-1", null_nl="null", alt_nl="alt")
    data_contract = DataContract(dataset_id="dataset-1", allowed_columns=["x1"])
    team = PopperppTeam(config, executor=ListExecutor([1.0, 0.01, 1e-6]))
    run = team.run(claim, data_contract, ConservationLedger())
    assert run.decision == "REJECT_H0"
    assert len(run.rounds) == 3
