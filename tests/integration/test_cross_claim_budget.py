from typing import Dict

from evidenceos.ledger.ledger import ConservationLedger
from evidenceos.schemas.popperpp import FalsificationConfig
from evidenceos.teams.popperpp.team import PopperppTeam
from evidenceos.teams.popperpp.types import ClaimContract, DataContract


class ConstantExecutor:
    def execute(self, subhypothesis, lane: str, context: Dict[str, object]) -> float:
        del subhypothesis, lane, context
        return 1.0


def test_cross_claim_dataset_budget() -> None:
    config = FalsificationConfig(
        alpha=0.2,
        kappa=0.5,
        max_rounds=3,
        max_failed_rounds=0,
        max_total_tests_per_claim=5,
        max_total_tests_per_dataset=1,
        lane_policy={"default": "CANARY"},
        selection_policy="uniform",
        allow_llm_design=False,
    )
    claim = ClaimContract(claim_id="claim-1", dataset_id="dataset-1", null_nl="null", alt_nl="alt")
    data_contract = DataContract(dataset_id="dataset-1", allowed_columns=["x1"])
    team = PopperppTeam(config, executor=ConstantExecutor())
    run = team.run(claim, data_contract, ConservationLedger())
    assert run.decision == "BUDGET_EXHAUSTED"
    assert len(run.rounds) == 1
