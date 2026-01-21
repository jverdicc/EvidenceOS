from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional, Protocol, Tuple

IntegrityState = Literal["Trusted", "Unknown", "Corrupted"]
EvidenceMerge = Literal["weighted_mean_evalues", "product_evalues"]
DPMerge = Literal["max_if_disjoint_else_sum", "sum", "max"]
IntegrityMerge = Literal["any_corrupted_invalid", "majority_corrupted_invalid"]
DropoutMode = Literal["fail_closed", "best_effort"]

@dataclass(frozen=True)
class DropoutPolicy:
    min_quorum: int = 1
    mode: DropoutMode = "fail_closed"

@dataclass(frozen=True)
class MergerCertificates:
    independence_certified: bool = False
    identity_disjointness_certified: bool = False

@dataclass(frozen=True)
class MergerPolicy:
    evidence_merge: EvidenceMerge = "weighted_mean_evalues"
    dp_merge: DPMerge = "max_if_disjoint_else_sum"
    integrity_merge: IntegrityMerge = "any_corrupted_invalid"
    dropout_policy: DropoutPolicy = field(default_factory=DropoutPolicy)
    certificates: MergerCertificates = field(default_factory=MergerCertificates)

@dataclass(frozen=True)
class VaultDescriptor:
    vault_id: str
    oracle_endpoint: str
    vault_pubkey_hex: str
    population_weight: Optional[float] = None
    supports_dp: bool = False
    supports_zk: bool = False
    supports_secagg: bool = False

@dataclass(frozen=True)
class FederationContract:
    federation_id: str
    claim_id: str
    frozen_plan_hash: str
    vaults: Tuple[VaultDescriptor, ...]
    merge_policy: MergerPolicy
    max_global_queries: Optional[int] = None
    max_adaptive_rounds: Optional[int] = None
    signatures: Tuple[str, ...] = ()

@dataclass(frozen=True)
class ScoreBucket:
    lower: float
    upper: float

@dataclass(frozen=True)
class FederatedOracleQuery:
    federation_id: str
    query_id: str
    candidate_id: str
    query_kind: Literal["score", "compare", "slice_score", "calibration"]
    requested_metric: str
    split: str
    target_vaults: Tuple[str, ...]
    slice: str = "all"
    nonce: str = ""
    timestamp_utc: Optional[str] = None

@dataclass(frozen=True)
class FederatedOracleResponse:
    federation_id: str
    query_id: str
    vault_id: str
    mode: str
    score_bucket: ScoreBucket
    e_value: Optional[float]
    response_hash: str
    signature: str

@dataclass(frozen=True)
class LocalLedgerSummary:
    vault_id: str
    integrity_state: IntegrityState
    evidence_lane: dict
    privacy_lane: dict
    adaptivity_lane: Optional[dict]
    summary_hash: str
    signature: str

@dataclass(frozen=True)
class GlobalLedger:
    integrity_state: IntegrityState
    e_value_global: Optional[float]
    epsilon_global: Optional[float]
    delta_global: Optional[float]
    violations: Tuple[str, ...]

class VaultOracle(Protocol):
    def freeze(self, federation_id: str, frozen_plan_hash: str) -> str: ...
    def query(self, q: FederatedOracleQuery) -> FederatedOracleResponse: ...
    def ledger_summary(self, federation_id: str) -> LocalLedgerSummary: ...
