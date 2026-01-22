from evidenceos.schemas.popperpp import (
    ArtifactRef,
    EvidenceLedgerRef,
    FalsificationConfig,
    FalsificationRun,
    RoundResult,
    SubHypothesis,
    TestObjectRef,
)


def test_popperpp_schema_validation() -> None:
    config = FalsificationConfig(
        alpha=0.05,
        kappa=0.5,
        max_rounds=3,
        max_failed_rounds=1,
        max_total_tests_per_claim=3,
        max_total_tests_per_dataset=10,
        lane_policy={"default": "CANARY"},
        selection_policy="uniform",
        allow_llm_design=False,
    )
    sub = SubHypothesis(
        id="sub-1",
        template="NEGATIVE_CONTROL",
        null_nl="null",
        alt_nl="alt",
        test_object=TestObjectRef(id="test-1", kind="NEGATIVE_CONTROL", params={}),
        metadata_only_ok=True,
    )
    round_result = RoundResult(
        round_idx=0,
        subhypothesis_id=sub.id,
        p_value=0.5,
        e_value=1.0,
        status="PASS",
        artifacts=[ArtifactRef(id="artifact-1", path="memory")],
    )
    run = FalsificationRun(
        claim_id="claim-1",
        dataset_id="dataset-1",
        config=config,
        rounds=[round_result],
        aggregated_e=1.0,
        decision="NO_DECISION",
        ledger_snapshot=EvidenceLedgerRef(id="ledger-1", snapshot={}),
    )
    assert run.model_dump()["claim_id"] == "claim-1"
