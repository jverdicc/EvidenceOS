from __future__ import annotations

from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TestObjectRef(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    lane_hint: Optional[str] = None
    params: Dict[str, object] = Field(default_factory=dict)


class ArtifactRef(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    sha256: Optional[str] = None


class EvidenceLedgerRef(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(min_length=1)
    snapshot: Dict[str, object]


class FalsificationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal["v1"] = "v1"
    alpha: float
    kappa: float
    max_rounds: int = Field(ge=1)
    max_failed_rounds: int = Field(ge=0)
    max_total_tests_per_claim: int = Field(ge=1)
    max_total_tests_per_dataset: int = Field(ge=1)
    lane_policy: Dict[str, str]
    selection_policy: Literal["greedy_expected_info", "uniform", "bandit_ucb"]
    allow_llm_design: bool = False

    @field_validator("alpha")
    @classmethod
    def _alpha_range(cls, value: float) -> float:
        if not 0 < value < 1:
            raise ValueError("alpha must be in (0, 1)")
        return value

    @field_validator("kappa")
    @classmethod
    def _kappa_range(cls, value: float) -> float:
        if not 0 < value < 1:
            raise ValueError("kappa must be in (0, 1)")
        return value


class SubHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal["v1"] = "v1"
    id: str = Field(min_length=1)
    template: Literal[
        "NEGATIVE_CONTROL",
        "PLACEBO",
        "SUBSET_INVARIANCE",
        "ALT_ESTIMATOR",
        "SHIFT_SLICE",
        "MULTIVERSE_SPEC",
    ]
    null_nl: str = Field(min_length=1)
    alt_nl: str = Field(min_length=1)
    test_object: TestObjectRef
    metadata_only_ok: bool = False


class RoundResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal["v1"] = "v1"
    round_idx: int = Field(ge=0)
    subhypothesis_id: str = Field(min_length=1)
    p_value: Optional[float] = Field(default=None, ge=0, le=1)
    e_value: Optional[float] = Field(default=None, ge=0)
    status: Literal["PASS", "FAIL", "SKIP", "ERROR"]
    artifacts: List[ArtifactRef]
    notes: Optional[str] = None


class FalsificationRun(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal["v1"] = "v1"
    claim_id: str = Field(min_length=1)
    dataset_id: str = Field(min_length=1)
    config: FalsificationConfig
    rounds: List[RoundResult]
    aggregated_e: float = Field(ge=0)
    decision: Literal["REJECT_H0", "NO_DECISION", "BUDGET_EXHAUSTED", "INVALID"]
    ledger_snapshot: EvidenceLedgerRef


def to_json_schema(model: type[BaseModel]) -> dict:
    return model.model_json_schema()
