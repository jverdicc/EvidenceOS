from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from evidenceos.evidence.priors import compute_prior_threshold
from evidenceos.ledger.ledger import ConservationLedger, LedgerViolation


@dataclass(frozen=True)
class DecisionTrace:
    status: str  # Supported / Rejected / Invalid / Inconclusive_DP_Limited
    reason: str
    e_value: Optional[float] = None
    dp_noise_margin: Optional[float] = None
    prior: Optional[float] = None
    threshold_multiplier: Optional[float] = None
    effective_threshold: Optional[float] = None


@dataclass(frozen=True)
class JudgePolicy:
    alpha: float = 0.05
    require_integrity_trusted: bool = True
    dp_significance_buffer: float = 0.0  # additional margin required to overcome DP noise floor


class Judge:
    def __init__(self, policy: JudgePolicy):
        self.policy = policy

    def evaluate(
        self,
        ledger: ConservationLedger,
        *,
        e_value: Optional[float],
        improvement: Optional[float] = None,
        dp_noise_floor: Optional[float] = None,
        prior: Optional[float] = None,
    ) -> DecisionTrace:
        # Fail closed on ledger violations or corrupted integrity
        try:
            ledger.fail_closed_if_corrupted()
        except LedgerViolation as e:
            return DecisionTrace(status="Invalid", reason=str(e), e_value=e_value)

        if self.policy.require_integrity_trusted and ledger.integrity.state != "Trusted":
            return DecisionTrace(status="Invalid", reason="integrity_not_trusted", e_value=e_value)

        prior_threshold = compute_prior_threshold(alpha=self.policy.alpha, prior=prior)

        if e_value is None:
            return DecisionTrace(
                status="Invalid",
                reason="missing_e_value",
                e_value=None,
                prior=prior_threshold.prior,
                threshold_multiplier=prior_threshold.multiplier,
                effective_threshold=prior_threshold.effective_threshold,
            )

        # DP-aware buffer rule
        if dp_noise_floor is not None and improvement is not None:
            margin = dp_noise_floor + self.policy.dp_significance_buffer
            if improvement < margin:
                return DecisionTrace(
                    status="Inconclusive_DP_Limited",
                    reason="improvement_below_dp_noise_floor",
                    e_value=e_value,
                    dp_noise_margin=margin,
                    prior=prior_threshold.prior,
                    threshold_multiplier=prior_threshold.multiplier,
                    effective_threshold=prior_threshold.effective_threshold,
                )

        # e-values: reject null if e_value >= 1/alpha
        threshold = prior_threshold.effective_threshold
        if e_value >= threshold:
            return DecisionTrace(
                status="Supported",
                reason="e_value_pass",
                e_value=e_value,
                prior=prior_threshold.prior,
                threshold_multiplier=prior_threshold.multiplier,
                effective_threshold=threshold,
            )
        return DecisionTrace(
            status="Rejected",
            reason="e_value_fail",
            e_value=e_value,
            prior=prior_threshold.prior,
            threshold_multiplier=prior_threshold.multiplier,
            effective_threshold=threshold,
        )
