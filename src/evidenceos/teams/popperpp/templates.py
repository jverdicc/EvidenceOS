from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from evidenceos.schemas.popperpp import SubHypothesis, TestObjectRef
from evidenceos.teams.popperpp.types import ClaimContract, DataContract


ALLOWED_TEMPLATES = {
    "NEGATIVE_CONTROL",
    "PLACEBO",
    "SUBSET_INVARIANCE",
    "ALT_ESTIMATOR",
    "SHIFT_SLICE",
    "MULTIVERSE_SPEC",
}

FORBIDDEN_FEATURES = {"target", "label", "outcome"}


def _validate_test_object(test_object: TestObjectRef, allowed_columns: List[str]) -> None:
    features = test_object.params.get("features", [])
    if not isinstance(features, list):
        raise ValueError("features must be list")
    forbidden = FORBIDDEN_FEATURES.intersection(set(features))
    if forbidden:
        raise ValueError("forbidden_feature:" + ",".join(sorted(forbidden)))
    if allowed_columns and any(col not in allowed_columns for col in features):
        raise ValueError("feature_not_allowed")


def validate_subhypothesis(subhypothesis: SubHypothesis, data_contract: DataContract) -> None:
    if subhypothesis.template not in ALLOWED_TEMPLATES:
        raise ValueError("template_not_allowed")
    _validate_test_object(subhypothesis.test_object, data_contract.allowed_columns)


def _base_test_object(kind: str, lane_hint: str | None, params: Dict[str, object]) -> TestObjectRef:
    return TestObjectRef(id=kind, kind=kind, lane_hint=lane_hint, params=params)


@dataclass
class NegativeControlGenerator:
    def generate(
        self, claim: ClaimContract, data_contract: DataContract, context: Dict[str, object]
    ) -> List[SubHypothesis]:
        test_object = _base_test_object(
            "NEGATIVE_CONTROL",
            "CANARY",
            {"features": data_contract.allowed_columns[:1], "mock_p_value": 1.0},
        )
        sub = SubHypothesis(
            id=f"{claim.claim_id}:negctrl",
            template="NEGATIVE_CONTROL",
            null_nl=f"{claim.null_nl} under negative control",
            alt_nl=f"{claim.alt_nl} under negative control",
            test_object=test_object,
            metadata_only_ok=True,
        )
        return [sub]


@dataclass
class PlaceboGenerator:
    def generate(
        self, claim: ClaimContract, data_contract: DataContract, context: Dict[str, object]
    ) -> List[SubHypothesis]:
        test_object = _base_test_object(
            "PLACEBO",
            "CANARY",
            {"features": data_contract.allowed_columns[:1], "mock_p_value": 0.5},
        )
        sub = SubHypothesis(
            id=f"{claim.claim_id}:placebo",
            template="PLACEBO",
            null_nl=f"{claim.null_nl} on placebo outcome",
            alt_nl=f"{claim.alt_nl} on placebo outcome",
            test_object=test_object,
            metadata_only_ok=True,
        )
        return [sub]


@dataclass
class SubsetInvarianceGenerator:
    def generate(
        self, claim: ClaimContract, data_contract: DataContract, context: Dict[str, object]
    ) -> List[SubHypothesis]:
        test_object = _base_test_object(
            "SUBSET_INVARIANCE",
            "FAST",
            {"features": data_contract.allowed_columns[:1], "mock_p_value": 0.2},
        )
        sub = SubHypothesis(
            id=f"{claim.claim_id}:subset",
            template="SUBSET_INVARIANCE",
            null_nl=f"{claim.null_nl} within subset",
            alt_nl=f"{claim.alt_nl} within subset",
            test_object=test_object,
            metadata_only_ok=True,
        )
        return [sub]


@dataclass
class AltEstimatorGenerator:
    def generate(
        self, claim: ClaimContract, data_contract: DataContract, context: Dict[str, object]
    ) -> List[SubHypothesis]:
        test_object = _base_test_object(
            "ALT_ESTIMATOR",
            "FAST",
            {"features": data_contract.allowed_columns[:1], "mock_p_value": 0.1},
        )
        sub = SubHypothesis(
            id=f"{claim.claim_id}:altest",
            template="ALT_ESTIMATOR",
            null_nl=f"{claim.null_nl} under alternate estimator",
            alt_nl=f"{claim.alt_nl} under alternate estimator",
            test_object=test_object,
            metadata_only_ok=True,
        )
        return [sub]


@dataclass
class ShiftSliceGenerator:
    def generate(
        self, claim: ClaimContract, data_contract: DataContract, context: Dict[str, object]
    ) -> List[SubHypothesis]:
        test_object = _base_test_object(
            "SHIFT_SLICE",
            "CANARY",
            {"features": data_contract.allowed_columns[:1], "mock_p_value": 0.05},
        )
        sub = SubHypothesis(
            id=f"{claim.claim_id}:shift",
            template="SHIFT_SLICE",
            null_nl=f"{claim.null_nl} under shift slice",
            alt_nl=f"{claim.alt_nl} under shift slice",
            test_object=test_object,
            metadata_only_ok=True,
        )
        return [sub]


@dataclass
class MultiverseSpecGenerator:
    def generate(
        self, claim: ClaimContract, data_contract: DataContract, context: Dict[str, object]
    ) -> List[SubHypothesis]:
        test_object = _base_test_object(
            "MULTIVERSE_SPEC",
            "SEALED",
            {"features": data_contract.allowed_columns[:1], "mock_p_value": 0.01},
        )
        sub = SubHypothesis(
            id=f"{claim.claim_id}:multiverse",
            template="MULTIVERSE_SPEC",
            null_nl=f"{claim.null_nl} across multiverse specs",
            alt_nl=f"{claim.alt_nl} across multiverse specs",
            test_object=test_object,
            metadata_only_ok=False,
        )
        return [sub]
