from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from evidenceos.admissibility.reality_kernel import RealityKernel
from evidenceos.common.canonical_json import canonical_dumps_str, stable_object_hash
from evidenceos.common.schema_validate import validate_json
from evidenceos.common.signing import Ed25519Keypair, sign_ed25519
from evidenceos.evidence.priors import compute_prior_threshold

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas" / "uvp"
CONFIG_SCHEMA = SCHEMA_DIR / "safety_case_config.schema.json"
SCC_SCHEMA = SCHEMA_DIR / "scc.schema.json"
HYPOTHESES_SCHEMA = SCHEMA_DIR / "hypotheses_batch.schema.json"


def _load_json(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    return payload


@dataclass(frozen=True)
class AdversarialHypothesis:
    hypothesis_id: str
    attack_description: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "attack_description": self.attack_description,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class SafetyCaseConfig:
    alpha: float
    prior: float
    p0: float
    p1: float
    bankruptcy_threshold: float | None
    enable_reality_kernel: bool
    reality_kernel_dir: str = "reality_kernel"

    @classmethod
    def from_session_dir(cls, session_dir: Path) -> SafetyCaseConfig:
        path = session_dir / "uvp_config.json"
        if not path.exists():
            raise FileNotFoundError("missing_uvp_config")
        payload = _load_json(path)
        validate_json(payload, CONFIG_SCHEMA)

        alpha = float(payload["alpha"])
        prior = float(payload["prior"])
        p0 = float(payload["p0"])
        p1 = float(payload["p1"])
        bankruptcy_threshold = payload.get("bankruptcy_threshold")
        enable_reality_kernel = bool(payload.get("enable_reality_kernel", False))
        reality_kernel_dir = str(payload.get("reality_kernel_dir", "reality_kernel"))

        if not (0.0 < alpha < 1.0):
            raise ValueError("alpha must be in (0,1)")
        if not (0.0 < prior <= 1.0):
            raise ValueError("prior must be in (0,1]")
        if not (0.0 < p0 < 1.0) or not (0.0 < p1 < 1.0):
            raise ValueError("p0 and p1 must be in (0,1)")
        if math.isclose(p0, p1):
            raise ValueError("p0 and p1 must differ")
        if bankruptcy_threshold is not None:
            bankruptcy_threshold = float(bankruptcy_threshold)
            if bankruptcy_threshold <= 0.0:
                raise ValueError("bankruptcy_threshold must be > 0")

        return cls(
            alpha=alpha,
            prior=prior,
            p0=p0,
            p1=p1,
            bankruptcy_threshold=bankruptcy_threshold,
            enable_reality_kernel=enable_reality_kernel,
            reality_kernel_dir=reality_kernel_dir,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "alpha": self.alpha,
            "prior": self.prior,
            "p0": self.p0,
            "p1": self.p1,
            "bankruptcy_threshold": self.bankruptcy_threshold,
            "enable_reality_kernel": self.enable_reality_kernel,
            "reality_kernel_dir": self.reality_kernel_dir,
        }


@dataclass
class EvidenceWealthLedger:
    alpha: float
    prior: float
    p0: float
    p1: float
    bankruptcy_threshold: float
    e_value: float = 1.0
    status: str = "IN_PROGRESS"
    support_threshold: float = field(init=False)

    def __post_init__(self) -> None:
        threshold = compute_prior_threshold(alpha=self.alpha, prior=self.prior)
        self.support_threshold = threshold.effective_threshold
        if self.bankruptcy_threshold <= 0.0:
            raise ValueError("bankruptcy_threshold must be > 0")

    def update(self, outcome: int) -> float:
        if outcome not in (0, 1):
            raise ValueError("outcome must be 0 or 1")
        if outcome == 1:
            factor = self.p1 / self.p0
        else:
            factor = (1.0 - self.p1) / (1.0 - self.p0)
        if not math.isfinite(factor) or factor <= 0.0:
            raise ValueError("invalid_evidence_factor")
        self.e_value *= factor
        if self.e_value >= self.support_threshold:
            self.status = "SUPPORTED+"
        elif self.e_value <= self.bankruptcy_threshold:
            self.status = "BANKRUPT"
        else:
            self.status = "IN_PROGRESS"
        return self.e_value

    def to_dict(self) -> dict[str, Any]:
        return {
            "alpha": self.alpha,
            "prior": self.prior,
            "p0": self.p0,
            "p1": self.p1,
            "e_value": self.e_value,
            "status": self.status,
            "support_threshold": self.support_threshold,
            "bankruptcy_threshold": self.bankruptcy_threshold,
        }


@dataclass(frozen=True)
class GateResult:
    status: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"status": self.status, "reason": self.reason}


@dataclass(frozen=True)
class SafetyCaseCounts:
    tested: int = 0
    gated_out: int = 0
    fails: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "tested": self.tested,
            "gated_out": self.gated_out,
            "fails": self.fails,
        }


@dataclass(frozen=True)
class DecisionTrace:
    status: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"status": self.status, "reason": self.reason}


@dataclass(frozen=True)
class UvpAnnounce:
    safety_property: str
    timestamp_utc: str
    kernel_pubkey: str

    def to_dict(self) -> dict[str, str]:
        return {
            "syscall": "announce",
            "safety_property": self.safety_property,
            "timestamp_utc": self.timestamp_utc,
            "kernel_pubkey": self.kernel_pubkey,
        }


@dataclass(frozen=True)
class UvpPropose:
    hypothesis: AdversarialHypothesis

    def to_dict(self) -> dict[str, Any]:
        return {"syscall": "propose", "hypothesis": self.hypothesis.to_dict()}


@dataclass(frozen=True)
class UvpEvaluate:
    hypothesis_id: str
    gated_out: bool
    outcome: int | None
    e_value: float | None
    ewl_status: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "syscall": "evaluate",
            "hypothesis_id": self.hypothesis_id,
            "gated_out": self.gated_out,
            "outcome": self.outcome,
            "e_value": self.e_value,
            "ewl_status": self.ewl_status,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class UvpCertify:
    decision: DecisionTrace
    counts: SafetyCaseCounts
    ewl_status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "syscall": "certify",
            "decision": self.decision.to_dict(),
            "counts": self.counts.to_dict(),
            "ewl_status": self.ewl_status,
        }


@dataclass(frozen=True)
class SCC:
    version: str
    safety_property: str
    timestamp_utc: str
    counts: SafetyCaseCounts
    decision: DecisionTrace
    ewl: Mapping[str, Any]
    transcript: Sequence[Mapping[str, Any]]
    transcript_hash: str
    kernel_pubkey: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "safety_property": self.safety_property,
            "timestamp_utc": self.timestamp_utc,
            "counts": self.counts.to_dict(),
            "decision": self.decision.to_dict(),
            "ewl": dict(self.ewl),
            "transcript": list(self.transcript),
            "transcript_hash": self.transcript_hash,
            "kernel_pubkey": self.kernel_pubkey,
            "signature": self.signature,
        }


def _gate_with_reality_kernel(session_dir: Path, config: SafetyCaseConfig) -> GateResult:
    if not config.enable_reality_kernel:
        return GateResult(status="PASS", reason="reality_kernel_disabled")
    kernel_dir = session_dir / config.reality_kernel_dir
    if not kernel_dir.exists():
        raise FileNotFoundError("missing_reality_kernel_dir")
    kernel = RealityKernel()
    result = kernel.validate_from_files(
        kernel_dir / "physhir.json",
        kernel_dir / "causal.json",
        kernel_dir / "config.json",
    )
    if result.ok:
        return GateResult(status="PASS", reason="reality_kernel_pass")
    reason = result.errors[0].code if result.errors else "reality_kernel_fail"
    return GateResult(status="FAIL", reason=reason)


def _decision_trace(gate: GateResult, ewl_status: str) -> DecisionTrace:
    if gate.status != "PASS":
        return DecisionTrace(status="Invalid", reason=gate.reason)
    if ewl_status == "SUPPORTED+":
        return DecisionTrace(status="SUPPORTED+", reason="e_value_threshold_met")
    if ewl_status == "BANKRUPT":
        return DecisionTrace(status="BANKRUPT", reason="bankruptcy_threshold_met")
    return DecisionTrace(status="IN_PROGRESS", reason="evidence_incomplete")


def uvp_announce(
    safety_property: str,
    timestamp_utc: str,
    kernel_keypair: Ed25519Keypair,
) -> UvpAnnounce:
    kernel_pubkey = "ed25519:" + kernel_keypair.public_key_bytes().hex()
    return UvpAnnounce(
        safety_property=safety_property,
        timestamp_utc=timestamp_utc,
        kernel_pubkey=kernel_pubkey,
    )


def uvp_propose(hypothesis: AdversarialHypothesis) -> UvpPropose:
    return UvpPropose(hypothesis=hypothesis)


def uvp_evaluate(
    hypothesis: AdversarialHypothesis,
    *,
    gate: GateResult,
    ewl: EvidenceWealthLedger,
    evaluator: Callable[[AdversarialHypothesis], int],
) -> UvpEvaluate:
    if gate.status != "PASS":
        return UvpEvaluate(
            hypothesis_id=hypothesis.hypothesis_id,
            gated_out=True,
            outcome=None,
            e_value=None,
            ewl_status=ewl.status,
            reason=gate.reason,
        )
    outcome = evaluator(hypothesis)
    if outcome not in (0, 1):
        raise ValueError("outcome must be 0 or 1")
    e_value = ewl.update(outcome)
    return UvpEvaluate(
        hypothesis_id=hypothesis.hypothesis_id,
        gated_out=False,
        outcome=outcome,
        e_value=e_value,
        ewl_status=ewl.status,
        reason="evaluated",
    )


def uvp_certify(
    *,
    safety_property: str,
    timestamp_utc: str,
    counts: SafetyCaseCounts,
    decision: DecisionTrace,
    ewl: EvidenceWealthLedger,
    transcript: Sequence[Mapping[str, Any]],
    kernel_keypair: Ed25519Keypair,
) -> SCC:
    transcript_hash = "sha256:" + stable_object_hash(transcript)
    kernel_pubkey = "ed25519:" + kernel_keypair.public_key_bytes().hex()
    scc_payload = {
        "version": "v1",
        "safety_property": safety_property,
        "timestamp_utc": timestamp_utc,
        "counts": counts.to_dict(),
        "decision": decision.to_dict(),
        "ewl": ewl.to_dict(),
        "transcript": list(transcript),
        "transcript_hash": transcript_hash,
        "kernel_pubkey": kernel_pubkey,
    }
    signature = sign_ed25519(kernel_keypair, scc_payload)
    scc_payload["signature"] = signature
    validate_json(scc_payload, SCC_SCHEMA)
    return SCC(
        version="v1",
        safety_property=safety_property,
        timestamp_utc=timestamp_utc,
        counts=counts,
        decision=decision,
        ewl=ewl.to_dict(),
        transcript=transcript,
        transcript_hash=transcript_hash,
        kernel_pubkey=kernel_pubkey,
        signature=signature,
    )


def load_hypotheses_batch(path: Path) -> list[AdversarialHypothesis]:
    payload = _load_json(path)
    validate_json(payload, HYPOTHESES_SCHEMA)
    hypotheses_raw = payload["hypotheses"]
    hypotheses: list[AdversarialHypothesis] = []
    for item in hypotheses_raw:
        metadata = item.get("metadata", {})
        hypotheses.append(
            AdversarialHypothesis(
                hypothesis_id=str(item["hypothesis_id"]),
                attack_description=str(item["attack_description"]),
                metadata=metadata,
            )
        )
    return hypotheses


def load_hypotheses_batch_with_outcomes(
    path: Path,
) -> tuple[list[AdversarialHypothesis], dict[str, int]]:
    payload = _load_json(path)
    validate_json(payload, HYPOTHESES_SCHEMA)
    outcome_map: dict[str, int] = {}
    hypotheses: list[AdversarialHypothesis] = []
    for item in payload["hypotheses"]:
        hypothesis_id = str(item["hypothesis_id"])
        hypotheses.append(
            AdversarialHypothesis(
                hypothesis_id=hypothesis_id,
                attack_description=str(item["attack_description"]),
                metadata=item.get("metadata", {}),
            )
        )
        outcome = int(item["outcome"])
        if outcome not in (0, 1):
            raise ValueError("outcome must be 0 or 1")
        outcome_map[hypothesis_id] = outcome
    return hypotheses, outcome_map


class SafetyCaseRunner:
    def run(
        self,
        session_dir: Path,
        safety_property: str,
        hypotheses: Sequence[AdversarialHypothesis],
        evaluator: Callable[[AdversarialHypothesis], int],
        kernel_keypair: Ed25519Keypair,
        timestamp_utc: str,
    ) -> SCC:
        config = SafetyCaseConfig.from_session_dir(session_dir)
        threshold = compute_prior_threshold(alpha=config.alpha, prior=config.prior)
        bankruptcy_threshold = config.bankruptcy_threshold or (1.0 / threshold.effective_threshold)
        ewl = EvidenceWealthLedger(
            alpha=config.alpha,
            prior=config.prior,
            p0=config.p0,
            p1=config.p1,
            bankruptcy_threshold=bankruptcy_threshold,
        )
        gate = _gate_with_reality_kernel(session_dir, config)

        transcript: list[Mapping[str, Any]] = []
        announce = uvp_announce(safety_property, timestamp_utc, kernel_keypair)
        transcript.append(announce.to_dict())

        counts = SafetyCaseCounts()
        for hypothesis in hypotheses:
            transcript.append(uvp_propose(hypothesis).to_dict())
            evaluation = uvp_evaluate(hypothesis, gate=gate, ewl=ewl, evaluator=evaluator)
            transcript.append(evaluation.to_dict())

            if evaluation.gated_out:
                counts = SafetyCaseCounts(
                    tested=counts.tested,
                    gated_out=counts.gated_out + 1,
                    fails=counts.fails,
                )
                continue
            tested = counts.tested + 1
            fails = counts.fails + (1 if evaluation.outcome == 1 else 0)
            counts = SafetyCaseCounts(tested=tested, gated_out=counts.gated_out, fails=fails)
            if ewl.status in ("SUPPORTED+", "BANKRUPT"):
                break

        decision = _decision_trace(gate, ewl.status)
        certify = UvpCertify(decision=decision, counts=counts, ewl_status=ewl.status)
        transcript.append(certify.to_dict())

        scc = uvp_certify(
            safety_property=safety_property,
            timestamp_utc=timestamp_utc,
            counts=counts,
            decision=decision,
            ewl=ewl,
            transcript=transcript,
            kernel_keypair=kernel_keypair,
        )
        return scc


def render_scc_json(scc: SCC) -> str:
    return canonical_dumps_str(scc.to_dict())
