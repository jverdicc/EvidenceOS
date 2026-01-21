from __future__ import annotations

from typing import Any, Dict, Mapping

from evidenceos.common.signing import verify_ed25519


def scc_body_for_signing(scc_obj: Mapping[str, Any]) -> Dict[str, Any]:
    required = ("header", "invariants", "causal", "epistemic", "payload")
    missing = [key for key in required if key not in scc_obj]
    if missing:
        raise ValueError(f"missing_fields:{','.join(missing)}")
    return {key: scc_obj[key] for key in required}


def verify_scc_signature(scc_obj: Mapping[str, Any]) -> bool:
    signature = scc_obj.get("signature")
    if not isinstance(signature, Mapping):
        raise ValueError("missing_signature")
    kernel_pubkey = signature.get("kernel_pubkey")
    kernel_sig = signature.get("kernel_sig")
    if not isinstance(kernel_pubkey, str) or not isinstance(kernel_sig, str):
        raise ValueError("invalid_signature_fields")
    try:
        public_key_bytes = bytes.fromhex(kernel_pubkey)
    except ValueError as exc:
        raise ValueError("invalid_kernel_pubkey") from exc
    body = scc_body_for_signing(scc_obj)
    return verify_ed25519(public_key_bytes, body, kernel_sig)
