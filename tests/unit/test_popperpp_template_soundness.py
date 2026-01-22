import pytest

from evidenceos.schemas.popperpp import TestObjectRef
from evidenceos.teams.popperpp.templates import (
    AltEstimatorGenerator,
    MultiverseSpecGenerator,
    NegativeControlGenerator,
    PlaceboGenerator,
    ShiftSliceGenerator,
    SubsetInvarianceGenerator,
    validate_subhypothesis,
)
from evidenceos.teams.popperpp.types import ClaimContract, DataContract


def test_template_generators_sound() -> None:
    claim = ClaimContract(claim_id="claim-1", dataset_id="dataset-1", null_nl="null", alt_nl="alt")
    data_contract = DataContract(dataset_id="dataset-1", allowed_columns=["x1", "x2"])
    generators = [
        NegativeControlGenerator(),
        PlaceboGenerator(),
        SubsetInvarianceGenerator(),
        AltEstimatorGenerator(),
        ShiftSliceGenerator(),
        MultiverseSpecGenerator(),
    ]
    for generator in generators:
        subs = generator.generate(claim, data_contract, {})
        assert subs
        for sub in subs:
            validate_subhypothesis(sub, data_contract)


def test_template_rejects_forbidden_features() -> None:
    claim = ClaimContract(claim_id="claim-1", dataset_id="dataset-1", null_nl="null", alt_nl="alt")
    data_contract = DataContract(dataset_id="dataset-1", allowed_columns=["x1"])
    sub = NegativeControlGenerator().generate(claim, data_contract, {})[0]
    sub.test_object = TestObjectRef(
        id="test-1",
        kind="NEGATIVE_CONTROL",
        params={"features": ["target"]},
    )
    with pytest.raises(ValueError):
        validate_subhypothesis(sub, data_contract)
