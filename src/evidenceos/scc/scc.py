from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from evidenceos.common.signing import Ed25519Keypair, sign_ed25519


@dataclass(frozen=True)
class SCCHeader:
    version: str
    uid: str

    def to_obj(self) -> Dict[str, Any]:
        return {"version": self.version, "uid": self.uid}


@dataclass(frozen=True)
class SCCInvariants:
    physhir: str
    details_hash: str

    def to_obj(self) -> Dict[str, Any]:
        return {"physhir": self.physhir, "details_hash": self.details_hash}


@dataclass(frozen=True)
class SCCCausal:
    dag_hash: str
    temporal_ok: bool
    backdoor_ok: bool
    canary_ok: bool

    def to_obj(self) -> Dict[str, Any]:
        return {
            "dag_hash": self.dag_hash,
            "temporal_ok": self.temporal_ok,
            "backdoor_ok": self.backdoor_ok,
            "canary_ok": self.canary_ok,
        }


@dataclass(frozen=True)
class SCCEpistemic:
    wealth: float
    alpha: float
    threshold: float
    prior: float
    cert: str

    def to_obj(self) -> Dict[str, Any]:
        return {
            "wealth": self.wealth,
            "alpha": self.alpha,
            "threshold": self.threshold,
            "prior": self.prior,
            "cert": self.cert,
        }


@dataclass(frozen=True)
class SCCPayload:
    hir_hash: str
    executable_hash: str

    def to_obj(self) -> Dict[str, Any]:
        return {"hir_hash": self.hir_hash, "executable_hash": self.executable_hash}


@dataclass(frozen=True)
class SCCSignature:
    kernel_pubkey: str
    kernel_sig: str
    timestamp_utc: str

    def to_obj(self) -> Dict[str, Any]:
        return {
            "kernel_pubkey": self.kernel_pubkey,
            "kernel_sig": self.kernel_sig,
            "timestamp_utc": self.timestamp_utc,
        }


@dataclass(frozen=True)
class SCC:
    header: SCCHeader
    invariants: SCCInvariants
    causal: SCCCausal
    epistemic: SCCEpistemic
    payload: SCCPayload
    signature: SCCSignature

    def to_obj(self) -> Dict[str, Any]:
        return {
            "header": self.header.to_obj(),
            "invariants": self.invariants.to_obj(),
            "causal": self.causal.to_obj(),
            "epistemic": self.epistemic.to_obj(),
            "payload": self.payload.to_obj(),
            "signature": self.signature.to_obj(),
        }


class SCCBuilder:
    """Builds a Standardized Claim Capsule (SCC).

    Signatures cover the canonicalized SCC body excluding the signature block.
    """

    def __init__(self, *, version: str = "UVP/1.0") -> None:
        self.version = version

    def build(
        self,
        *,
        uid: str,
        invariants: SCCInvariants,
        causal: SCCCausal,
        epistemic: SCCEpistemic,
        payload: SCCPayload,
        keypair: Ed25519Keypair,
        timestamp_utc: str,
    ) -> SCC:
        header = SCCHeader(version=self.version, uid=uid)
        body = _scc_body_obj(
            header=header,
            invariants=invariants,
            causal=causal,
            epistemic=epistemic,
            payload=payload,
        )
        kernel_sig = sign_ed25519(keypair, body)
        signature = SCCSignature(
            kernel_pubkey=keypair.public_key_bytes().hex(),
            kernel_sig=kernel_sig,
            timestamp_utc=timestamp_utc,
        )
        return SCC(
            header=header,
            invariants=invariants,
            causal=causal,
            epistemic=epistemic,
            payload=payload,
            signature=signature,
        )


def _scc_body_obj(
    *,
    header: SCCHeader,
    invariants: SCCInvariants,
    causal: SCCCausal,
    epistemic: SCCEpistemic,
    payload: SCCPayload,
) -> Dict[str, Any]:
    return {
        "header": header.to_obj(),
        "invariants": invariants.to_obj(),
        "causal": causal.to_obj(),
        "epistemic": epistemic.to_obj(),
        "payload": payload.to_obj(),
    }
