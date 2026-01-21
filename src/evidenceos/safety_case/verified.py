# Copyright 2026 Joseph Verdicchio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from evidenceos.admissibility.reality_kernel import AdmissibilityResult, RealityKernel
from evidenceos.capsule.scc import StandardizedClaimCapsuleBuilder
from evidenceos.judge.judge import DecisionTrace, Judge, JudgePolicy
from evidenceos.ledger.ledger import ConservationLedger, LedgerViolation
from evidenceos.uvp.syscalls import UVPInterface, UVPTranscript


@dataclass(frozen=True)
class VerifiedSafetyCaseInput:
    claim_id: str
    claim: str
    safety_properties: tuple[str, ...]
    adversarial_hypotheses: tuple[str, ...]
    evidence_items: tuple[str, ...]
    physhir: dict[str, Any]
    causal: dict[str, Any]
    reality_config: dict[str, Any]
    e_value: float
    alpha: float
    prior: float | None
    resource_cost: float
    build_utc: str
    bankruptcy_threshold: float = 1e-12

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "VerifiedSafetyCaseInput":
        claim = payload["claim"]
        if not isinstance(claim, str) or not claim:
            raise ValueError("claim must be a non-empty string")
        claim_id = payload["claim_id"]
        if not isinstance(claim_id, str) or not claim_id:
            raise ValueError("claim_id must be a non-empty string")
        safety_properties = tuple(sorted(set(payload["safety_properties"])))
        adversarial_hypotheses = tuple(sorted(set(payload["adversarial_hypotheses"])))
        evidence_items = tuple(sorted(set(payload["evidence_items"])))
        resource_cost = float(payload.get("resource_cost", 0.0))
        if resource_cost < 0.0:
            raise ValueError("resource_cost must be >= 0")
        bankruptcy_threshold = float(payload.get("bankruptcy_threshold", 1e-12))
        if bankruptcy_threshold <= 0.0:
            raise ValueError("bankruptcy_threshold must be > 0")
        prior_value = payload.get("prior")
        normalized_prior = float(prior_value) if prior_value is not None else None
        return cls(
            claim_id=claim_id,
            claim=claim,
            safety_properties=safety_properties,
            adversarial_hypotheses=adversarial_hypotheses,
            evidence_items=evidence_items,
            physhir=dict(payload["reality_kernel"]["physhir"]),
            causal=dict(payload["reality_kernel"]["causal"]),
            reality_config=dict(payload["reality_kernel"]["config"]),
            e_value=float(payload["e_value"]),
            alpha=float(payload["alpha"]),
            prior=normalized_prior,
            resource_cost=resource_cost,
            build_utc=str(payload["build_utc"]),
            bankruptcy_threshold=bankruptcy_threshold,
        )


@dataclass(frozen=True)
class VerifiedSafetyCaseOutput:
    capsule_root: str
    decision_trace: DecisionTrace
    transcript: UVPTranscript
    reality_result: AdmissibilityResult


class VerifiedSafetyCasePipeline:
    def __init__(self, kernel: RealityKernel | None = None) -> None:
        self.kernel = kernel or RealityKernel()

    def run(self, inputs: VerifiedSafetyCaseInput, capsule_dir: Path) -> VerifiedSafetyCaseOutput:
        transcript = UVPTranscript()
        uvp = UVPInterface(transcript)
        ledger = ConservationLedger()
        ledger.wealth.bankruptcy_threshold = inputs.bankruptcy_threshold

        announce = uvp.announce(
            claim_id=inputs.claim_id,
            claim=inputs.claim,
            safety_properties=inputs.safety_properties,
            adversarial_hypotheses=inputs.adversarial_hypotheses,
        )

        proposal = uvp.propose(
            announcement_hash=announce.announcement_hash,
            evidence_items=inputs.evidence_items,
            resources_requested=inputs.resource_cost,
        )

        reality_result = self.kernel.validate_payloads(
            inputs.physhir, inputs.causal, inputs.reality_config
        )
        if not reality_result.ok:
            decision = DecisionTrace(status="Invalid", reason=reality_result.errors[0].code)
            uvp.evaluate(
                proposal_hash=proposal.proposal_hash,
                reality_status=reality_result.status,
                resources_spent=0.0,
                wealth_after=ledger.wealth.wealth,
            )
            uvp.certify(
                evaluation_hash=transcript.events[-1].payload_hash,
                decision_trace=_decision_trace_obj(decision),
            )
            return self._finalize(
                inputs=inputs,
                capsule_dir=capsule_dir,
                transcript=transcript,
                decision_trace=decision,
                reality_result=reality_result,
                ledger=ledger,
            )

        try:
            ledger.evidence.charge(inputs.resource_cost)
            ledger.wealth.apply_e_value(inputs.e_value)
            ledger.fail_closed_if_corrupted()
        except LedgerViolation as exc:
            decision = DecisionTrace(status="Invalid", reason=str(exc))
            uvp.evaluate(
                proposal_hash=proposal.proposal_hash,
                reality_status=reality_result.status,
                resources_spent=0.0,
                wealth_after=ledger.wealth.wealth,
            )
            uvp.certify(
                evaluation_hash=transcript.events[-1].payload_hash,
                decision_trace=_decision_trace_obj(decision),
            )
            return self._finalize(
                inputs=inputs,
                capsule_dir=capsule_dir,
                transcript=transcript,
                decision_trace=decision,
                reality_result=reality_result,
                ledger=ledger,
            )

        evaluation = uvp.evaluate(
            proposal_hash=proposal.proposal_hash,
            reality_status=reality_result.status,
            resources_spent=inputs.resource_cost,
            wealth_after=ledger.wealth.wealth,
        )

        judge = Judge(JudgePolicy(alpha=inputs.alpha))
        decision = judge.evaluate(
            ledger,
            e_value=inputs.e_value,
            prior=inputs.prior,
        )

        uvp.certify(
            evaluation_hash=evaluation.evaluation_hash,
            decision_trace=_decision_trace_obj(decision),
        )

        return self._finalize(
            inputs=inputs,
            capsule_dir=capsule_dir,
            transcript=transcript,
            decision_trace=decision,
            reality_result=reality_result,
            ledger=ledger,
        )

    def _finalize(
        self,
        *,
        inputs: VerifiedSafetyCaseInput,
        capsule_dir: Path,
        transcript: UVPTranscript,
        decision_trace: DecisionTrace,
        reality_result: AdmissibilityResult,
        ledger: ConservationLedger,
    ) -> VerifiedSafetyCaseOutput:
        builder = StandardizedClaimCapsuleBuilder()
        capsule_root = builder.build(
            capsule_dir,
            claim={
                "claim_id": inputs.claim_id,
                "claim": inputs.claim,
                "safety_properties": list(inputs.safety_properties),
                "adversarial_hypotheses": list(inputs.adversarial_hypotheses),
            },
            safety_case={
                "evidence_items": list(inputs.evidence_items),
                "resource_cost": inputs.resource_cost,
                "alpha": inputs.alpha,
                "prior": inputs.prior,
                "e_value": inputs.e_value,
            },
            reality_kernel_inputs={
                "physhir": inputs.physhir,
                "causal": inputs.causal,
                "config": inputs.reality_config,
            },
            uvp_transcript=transcript.to_obj(),
            ewl={
                "wealth": ledger.wealth.wealth,
                "bankruptcy_threshold": ledger.wealth.bankruptcy_threshold,
                "history": list(ledger.wealth.history),
            },
            decision_trace=_decision_trace_obj(decision_trace),
            build_utc=inputs.build_utc,
        )
        return VerifiedSafetyCaseOutput(
            capsule_root=capsule_root,
            decision_trace=decision_trace,
            transcript=transcript,
            reality_result=reality_result,
        )


def _decision_trace_obj(decision: DecisionTrace) -> dict[str, Any]:
    return {
        "status": decision.status,
        "reason": decision.reason,
        "e_value": decision.e_value,
        "dp_noise_margin": decision.dp_noise_margin,
        "prior": decision.prior,
        "threshold_multiplier": decision.threshold_multiplier,
        "effective_threshold": decision.effective_threshold,
    }


__all__ = ["VerifiedSafetyCaseInput", "VerifiedSafetyCaseOutput", "VerifiedSafetyCasePipeline"]
