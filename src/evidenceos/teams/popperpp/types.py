from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Protocol

from evidenceos.schemas.popperpp import SubHypothesis


@dataclass
class ClaimContract:
    claim_id: str
    dataset_id: str
    null_nl: str
    alt_nl: str


@dataclass
class DataContract:
    dataset_id: str
    allowed_columns: List[str]


@dataclass
class LeakageReport:
    ok: bool
    reason: Optional[str] = None


class LeakageGate(Protocol):
    def evaluate(self, claim: ClaimContract, data_contract: DataContract) -> LeakageReport: ...


class CandidateGenerator(Protocol):
    def generate(
        self, claim: ClaimContract, data_contract: DataContract, context: Dict[str, object]
    ) -> List[SubHypothesis]: ...


class RoundExecutor(Protocol):
    def execute(
        self, subhypothesis: SubHypothesis, lane: str, context: Dict[str, object]
    ) -> float: ...


class Selector(Protocol):
    def choose(self, candidates: Iterable[SubHypothesis]) -> SubHypothesis: ...
