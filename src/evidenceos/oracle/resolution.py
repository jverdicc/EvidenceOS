from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Optional

from evidenceos.common.encoding import encode_fixed_width_int
from evidenceos.ledger.ledger import ConservationLedger


@dataclass(frozen=True)
class OracleResolution:
    buckets: int
    min_value: float
    max_value: float
    hysteresis_delta: float

    def __post_init__(self) -> None:
        if self.buckets <= 1:
            raise ValueError("buckets must be > 1")
        if not math.isfinite(self.min_value) or not math.isfinite(self.max_value):
            raise ValueError("range must be finite")
        if self.max_value <= self.min_value:
            raise ValueError("max_value must be > min_value")
        if self.hysteresis_delta < 0:
            raise ValueError("hysteresis_delta must be >= 0")

    @property
    def bucket_bits(self) -> int:
        return int(math.ceil(math.log2(self.buckets)))

    @property
    def leakage_bits(self) -> float:
        return math.log2(self.buckets)

    def quantize(self, score: float) -> tuple[int, float, float]:
        if not math.isfinite(score):
            raise ValueError("score must be finite")
        clamped = min(max(score, self.min_value), self.max_value)
        width = (self.max_value - self.min_value) / self.buckets
        idx = int(math.floor((clamped - self.min_value) / width))
        if idx >= self.buckets:
            idx = self.buckets - 1
        lower = self.min_value + idx * width
        upper = lower + width
        return idx, lower, upper

    def encode_symbol(self, bucket_index: int) -> bytes:
        return encode_fixed_width_int(bucket_index, self.bucket_bits)


@dataclass
class QuantizedOracleState:
    last_score: Optional[float] = None
    last_bucket: Optional[int] = None


@dataclass(frozen=True)
class QuantizedOracleResult:
    bucket_index: int
    lower: float
    upper: float
    encoded: bytes


class QuantizedOracle:
    def __init__(self, *, resolution: OracleResolution, dataset_id: str) -> None:
        if not dataset_id:
            raise ValueError("dataset_id must be non-empty")
        self.resolution = resolution
        self.dataset_id = dataset_id
        self.state = QuantizedOracleState()

    def query(
        self,
        ledger: ConservationLedger,
        *,
        score: float,
        local: bool = False,
        charge_adaptivity: bool = True,
    ) -> QuantizedOracleResult:
        if charge_adaptivity:
            ledger.adaptivity.charge_query(1)
        ledger.leakage.charge(self.dataset_id, self.resolution.leakage_bits)

        bucket_index, lower, upper = self.resolution.quantize(score)
        if (
            local
            and self.state.last_score is not None
            and self.state.last_bucket is not None
            and abs(score - self.state.last_score) < self.resolution.hysteresis_delta
        ):
            bucket_index = self.state.last_bucket
            lower, upper = self.resolution.quantize(self.state.last_score)[1:]
        else:
            self.state.last_score = score
            self.state.last_bucket = bucket_index

        encoded = self.resolution.encode_symbol(bucket_index)
        return QuantizedOracleResult(bucket_index=bucket_index, lower=lower, upper=upper, encoded=encoded)
