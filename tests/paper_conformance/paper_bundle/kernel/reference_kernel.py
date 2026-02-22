"""Paper bundle reference kernel model used for conformance tests."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReferenceLedger:
    alpha: float
    k_bits_budget: float | None = None
    access_credit_budget: float | None = None
    k_bits_total: float = 0.0
    epsilon_total: float = 0.0
    delta_total: float = 0.0
    access_credit_spent: float = 0.0
    wealth: float = 1.0
    w_max: float = 1.0
    frozen: bool = False
    events: list[dict[str, Any]] = field(default_factory=list)

    def alpha_prime(self) -> float:
        return math.exp(math.log(self.alpha) - (self.k_bits_total * math.log(2.0)))

    def certification_barrier(self) -> float:
        return 1.0 / self.alpha_prime()

    def _budget_check(self, next_k: float, next_access: float) -> bool:
        if self.k_bits_budget is not None and next_k > self.k_bits_budget + sys_float_epsilon():
            self.frozen = True
            self.events.append({"kind": "freeze_budget_exhausted", "bits": 0.0})
            return True
        if self.access_credit_budget is not None and next_access > self.access_credit_budget + sys_float_epsilon():
            self.frozen = True
            self.events.append({"kind": "freeze_access_credit_exhausted", "bits": 0.0})
            return True
        return False

    def charge_all(
        self,
        *,
        k_bits: float,
        epsilon: float,
        delta: float,
        access_credit: float,
        event_kind: str,
        meta: dict[str, Any],
    ) -> bool:
        if self.frozen:
            return False
        next_k = self.k_bits_total + k_bits
        next_access = self.access_credit_spent + access_credit
        if self._budget_check(next_k, next_access):
            return False
        self.k_bits_total = next_k
        self.epsilon_total += epsilon
        self.delta_total += delta
        self.access_credit_spent = next_access
        self.events.append({"kind": event_kind, "bits": k_bits, "meta": meta})
        return True

    def charge_kout_bits(self, *, kout_bits: float) -> bool:
        return self.charge_all(
            k_bits=kout_bits,
            epsilon=0.0,
            delta=0.0,
            access_credit=kout_bits,
            event_kind="structured_output_kout",
            meta={"kout_bits": kout_bits},
        )

    def settle_e_value(self, *, e_value: float, event_kind: str, meta: dict[str, Any]) -> bool:
        if self.frozen:
            return False
        self.wealth *= e_value
        self.w_max = max(self.w_max, self.wealth)
        self.events.append({"kind": event_kind, "bits": 0.0, "meta": {**meta, "e_value": e_value}})
        return True


def sys_float_epsilon() -> float:
    return 2.220446049250313e-16
