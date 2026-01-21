from __future__ import annotations

from pathlib import Path

from evidenceos.common.schema_validate import validate_json
from evidenceos.common.signing import Ed25519Keypair
from evidenceos.scc.scc import SCCBuilder, SCCCausal, SCCEpistemic, SCCInvariants, SCCPayload
from evidenceos.scc.scc_verify import verify_scc_signature


def _schema_path() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "src"
        / "evidenceos"
        / "schemas"
        / "scc"
        / "scc.schema.json"
    )


def _build_scc() -> dict:
    builder = SCCBuilder()
    keypair = Ed25519Keypair.generate()
    scc = builder.build(
        uid="claim-001",
        invariants=SCCInvariants(physhir="PASS", details_hash="sha256:abc123"),
        causal=SCCCausal(
            dag_hash="sha256:def456",
            temporal_ok=True,
            backdoor_ok=True,
            canary_ok=True,
        ),
        epistemic=SCCEpistemic(
            wealth=452.1,
            alpha=0.05,
            threshold=20.0,
            prior=1.0,
            cert="SUPPORTED+",
        ),
        payload=SCCPayload(
            hir_hash="sha256:hir789",
            executable_hash="sha256:exe000",
        ),
        keypair=keypair,
        timestamp_utc="2026-01-21T09:00:00Z",
    )
    return scc.to_obj()


def test_scc_build_verify_signature() -> None:
    scc_obj = _build_scc()

    assert verify_scc_signature(scc_obj)


def test_scc_verify_signature_fails_on_tamper() -> None:
    scc_obj = _build_scc()
    scc_obj["epistemic"]["wealth"] = 999.9

    assert not verify_scc_signature(scc_obj)


def test_scc_schema_validation() -> None:
    scc_obj = _build_scc()

    validate_json(scc_obj, _schema_path())
