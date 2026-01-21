from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from evidenceos.common.canonical_json import canonical_dumps_bytes
from evidenceos.common.hashing import sha256_prefixed


def _normalize_strings(values: Sequence[str]) -> list[str]:
    if any(not isinstance(v, str) or not v for v in values):
        raise ValueError("all entries must be non-empty strings")
    return sorted(set(values))


def _hash_payload(payload: Mapping[str, Any]) -> str:
    return sha256_prefixed(canonical_dumps_bytes(payload))


@dataclass(frozen=True)
class UVPEvent:
    seq: int
    syscall: str
    payload: dict[str, Any]
    payload_hash: str

    def to_obj(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "syscall": self.syscall,
            "payload_hash": self.payload_hash,
            "payload": self.payload,
        }


@dataclass
class UVPTranscript:
    version: str = "v1"
    events: list[UVPEvent] = field(default_factory=list)

    def append(self, syscall: str, payload: Mapping[str, Any]) -> UVPEvent:
        seq = len(self.events) + 1
        payload_dict = dict(payload)
        payload_hash = _hash_payload(payload_dict)
        event = UVPEvent(seq=seq, syscall=syscall, payload=payload_dict, payload_hash=payload_hash)
        self.events.append(event)
        return event

    def to_obj(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "events": [event.to_obj() for event in self.events],
        }


@dataclass(frozen=True)
class UVPAnnouncement:
    claim_id: str
    claim: str
    safety_properties: tuple[str, ...]
    adversarial_hypotheses: tuple[str, ...]
    announcement_hash: str


@dataclass(frozen=True)
class UVPProposal:
    announcement_hash: str
    evidence_items: tuple[str, ...]
    resources_requested: float
    proposal_hash: str


@dataclass(frozen=True)
class UVPEvaluation:
    proposal_hash: str
    reality_status: str
    resources_spent: float
    wealth_after: float
    evaluation_hash: str


@dataclass(frozen=True)
class UVPCertification:
    evaluation_hash: str
    decision_trace: dict[str, Any]
    certification_hash: str


class UVPInterface:
    def __init__(self, transcript: UVPTranscript | None = None) -> None:
        self.transcript = transcript or UVPTranscript()

    def announce(
        self,
        *,
        claim_id: str,
        claim: str,
        safety_properties: Sequence[str],
        adversarial_hypotheses: Sequence[str],
    ) -> UVPAnnouncement:
        if not claim_id:
            raise ValueError("claim_id required")
        if not claim:
            raise ValueError("claim required")
        payload = {
            "claim_id": claim_id,
            "claim": claim,
            "safety_properties": _normalize_strings(safety_properties),
            "adversarial_hypotheses": _normalize_strings(adversarial_hypotheses),
        }
        event = self.transcript.append("announce", payload)
        return UVPAnnouncement(
            claim_id=claim_id,
            claim=claim,
            safety_properties=tuple(payload["safety_properties"]),
            adversarial_hypotheses=tuple(payload["adversarial_hypotheses"]),
            announcement_hash=event.payload_hash,
        )

    def propose(
        self,
        *,
        announcement_hash: str,
        evidence_items: Sequence[str],
        resources_requested: float,
    ) -> UVPProposal:
        if resources_requested < 0:
            raise ValueError("resources_requested must be >= 0")
        if not announcement_hash:
            raise ValueError("announcement_hash required")
        payload = {
            "announcement_hash": announcement_hash,
            "evidence_items": _normalize_strings(evidence_items),
            "resources_requested": resources_requested,
        }
        event = self.transcript.append("propose", payload)
        return UVPProposal(
            announcement_hash=announcement_hash,
            evidence_items=tuple(payload["evidence_items"]),
            resources_requested=resources_requested,
            proposal_hash=event.payload_hash,
        )

    def evaluate(
        self,
        *,
        proposal_hash: str,
        reality_status: str,
        resources_spent: float,
        wealth_after: float,
    ) -> UVPEvaluation:
        if not proposal_hash:
            raise ValueError("proposal_hash required")
        if resources_spent < 0:
            raise ValueError("resources_spent must be >= 0")
        payload = {
            "proposal_hash": proposal_hash,
            "reality_status": reality_status,
            "resources_spent": resources_spent,
            "wealth_after": wealth_after,
        }
        event = self.transcript.append("evaluate", payload)
        return UVPEvaluation(
            proposal_hash=proposal_hash,
            reality_status=reality_status,
            resources_spent=resources_spent,
            wealth_after=wealth_after,
            evaluation_hash=event.payload_hash,
        )

    def certify(
        self,
        *,
        evaluation_hash: str,
        decision_trace: Mapping[str, Any],
    ) -> UVPCertification:
        if not evaluation_hash:
            raise ValueError("evaluation_hash required")
        payload = {"evaluation_hash": evaluation_hash, "decision_trace": dict(decision_trace)}
        event = self.transcript.append("certify", payload)
        return UVPCertification(
            evaluation_hash=evaluation_hash,
            decision_trace=payload["decision_trace"],
            certification_hash=event.payload_hash,
        )


__all__ = [
    "UVPAnnouncement",
    "UVPCertification",
    "UVPEvaluation",
    "UVPEvent",
    "UVPInterface",
    "UVPProposal",
    "UVPTranscript",
]
