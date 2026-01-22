from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from evidenceos.ledger.ledger import ConservationLedger, LedgerViolation
from evidenceos.schemas.popperpp import (
    ArtifactRef,
    EvidenceLedgerRef,
    FalsificationConfig,
    FalsificationRun,
    RoundResult,
    SubHypothesis,
)
from evidenceos.stats.eprocess import EProcess
from evidenceos.stats.evalues import p_to_e_calibrator
from evidenceos.teams.popperpp.selector import BanditUCBSelector, GreedyExpectedInfoSelector, UniformSelector
from evidenceos.teams.popperpp.templates import (
    AltEstimatorGenerator,
    MultiverseSpecGenerator,
    NegativeControlGenerator,
    PlaceboGenerator,
    ShiftSliceGenerator,
    SubsetInvarianceGenerator,
    validate_subhypothesis,
)
from evidenceos.teams.popperpp.types import (
    CandidateGenerator,
    ClaimContract,
    DataContract,
    LeakageGate,
    LeakageReport,
    RoundExecutor,
)


@dataclass
class NoopLeakageGate:
    def evaluate(self, claim: ClaimContract, data_contract: DataContract) -> LeakageReport:
        return LeakageReport(ok=True)


@dataclass
class DefaultRoundExecutor:
    def execute(self, subhypothesis: SubHypothesis, lane: str, context: Dict[str, object]) -> float:
        del lane
        mock_p = subhypothesis.test_object.params.get("mock_p_value")
        if mock_p is None:
            raise ValueError("missing_mock_p_value")
        return float(mock_p)


@dataclass
class PopperppState:
    tests_per_claim: int = 0
    tests_per_dataset: int = 0
    failed_rounds: int = 0


class PopperppTeam:
    def __init__(
        self,
        config: FalsificationConfig,
        generators: Optional[Iterable[CandidateGenerator]] = None,
        leakage_gate: Optional[LeakageGate] = None,
        selector_policy: Optional[str] = None,
        executor: Optional[RoundExecutor] = None,
    ) -> None:
        self.config = config
        self.generators = list(
            generators
            if generators is not None
            else [
                NegativeControlGenerator(),
                PlaceboGenerator(),
                SubsetInvarianceGenerator(),
                AltEstimatorGenerator(),
                ShiftSliceGenerator(),
                MultiverseSpecGenerator(),
            ]
        )
        self.leakage_gate = leakage_gate or NoopLeakageGate()
        self.executor = executor or DefaultRoundExecutor()
        policy = selector_policy or config.selection_policy
        if policy == "greedy_expected_info":
            self.selector = GreedyExpectedInfoSelector()
        elif policy == "uniform":
            self.selector = UniformSelector()
        elif policy == "bandit_ucb":
            self.selector = BanditUCBSelector()
        else:
            raise ValueError("unknown_selection_policy")

    def _resolve_lane(self, subhypothesis: SubHypothesis) -> str:
        round_key = subhypothesis.template
        lane = self.config.lane_policy.get(round_key) or self.config.lane_policy.get("default")
        if lane is None:
            raise ValueError("lane_policy_missing")
        if lane == "FAST":
            return "CANARY"
        return lane

    def _ledger_snapshot(self, ledger: ConservationLedger) -> dict:
        return {
            "evidence": {
                "e_wealth_spent": ledger.evidence.e_wealth_spent,
                "e_wealth_max": ledger.evidence.e_wealth_max,
            },
            "adaptivity": {
                "holdout_queries_used": ledger.adaptivity.holdout_queries_used,
                "holdout_queries_max": ledger.adaptivity.holdout_queries_max,
                "adaptive_rounds_used": ledger.adaptivity.adaptive_rounds_used,
                "adaptive_rounds_max": ledger.adaptivity.adaptive_rounds_max,
            },
            "privacy": {
                "enabled": ledger.privacy.enabled,
                "epsilon_spent": ledger.privacy.epsilon_spent,
                "delta_spent": ledger.privacy.delta_spent,
                "epsilon_max": ledger.privacy.epsilon_max,
                "delta_max": ledger.privacy.delta_max,
            },
            "integrity": {
                "state": ledger.integrity.state,
                "flags": ledger.integrity.flags,
            },
            "wealth": {
                "wealth": ledger.wealth.wealth,
                "history": ledger.wealth.history,
                "bankruptcy_threshold": ledger.wealth.bankruptcy_threshold,
            },
        }

    def run(
        self, claim: ClaimContract, data_contract: DataContract, ledger: ConservationLedger
    ) -> FalsificationRun:
        leakage = self.leakage_gate.evaluate(claim, data_contract)
        rounds: List[RoundResult] = []
        state = PopperppState()
        eprocess = EProcess(alpha=self.config.alpha)
        decision = "NO_DECISION"
        if not leakage.ok:
            decision = "INVALID"
        if decision == "INVALID":
            return FalsificationRun(
                claim_id=claim.claim_id,
                dataset_id=claim.dataset_id,
                config=self.config,
                rounds=rounds,
                aggregated_e=eprocess.value(),
                decision=decision,
                ledger_snapshot=EvidenceLedgerRef(
                    id=f"ledger:{claim.claim_id}", snapshot=self._ledger_snapshot(ledger)
                ),
            )

        context: Dict[str, object] = {}
        candidates: List[SubHypothesis] = []
        for generator in self.generators:
            candidates.extend(generator.generate(claim, data_contract, context))

        for subhypothesis in candidates:
            validate_subhypothesis(subhypothesis, data_contract)

        for round_idx in range(self.config.max_rounds):
            if state.tests_per_claim >= self.config.max_total_tests_per_claim:
                decision = "BUDGET_EXHAUSTED"
                break
            if state.tests_per_dataset >= self.config.max_total_tests_per_dataset:
                decision = "BUDGET_EXHAUSTED"
                break
            if state.failed_rounds >= self.config.max_failed_rounds:
                decision = "BUDGET_EXHAUSTED"
                break
            chosen = self.selector.choose(candidates)
            lane = self._resolve_lane(chosen)
            try:
                ledger.adaptivity.charge_query(1)
                p_value = self.executor.execute(chosen, lane, context)
                e_value = p_to_e_calibrator(p_value, self.config.kappa)
                eprocess.observe(e_value)
                ledger.wealth.apply_e_value(e_value)
                result = RoundResult(
                    round_idx=round_idx,
                    subhypothesis_id=chosen.id,
                    p_value=p_value,
                    e_value=e_value,
                    status="PASS",
                    artifacts=[ArtifactRef(id=f"artifact:{round_idx}", path="memory")],
                )
            except (ValueError, LedgerViolation) as exc:
                state.failed_rounds += 1
                result = RoundResult(
                    round_idx=round_idx,
                    subhypothesis_id=chosen.id,
                    p_value=None,
                    e_value=None,
                    status="ERROR",
                    artifacts=[ArtifactRef(id=f"artifact:{round_idx}", path="memory")],
                    notes=str(exc),
                )
            rounds.append(result)
            state.tests_per_claim += 1
            state.tests_per_dataset += 1
            if eprocess.crossed():
                decision = "REJECT_H0"
                break

        return FalsificationRun(
            claim_id=claim.claim_id,
            dataset_id=claim.dataset_id,
            config=self.config,
            rounds=rounds,
            aggregated_e=eprocess.value(),
            decision=decision,
            ledger_snapshot=EvidenceLedgerRef(
                id=f"ledger:{claim.claim_id}", snapshot=self._ledger_snapshot(ledger)
            ),
        )
