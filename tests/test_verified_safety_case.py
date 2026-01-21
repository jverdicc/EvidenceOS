from pathlib import Path
import json
import tempfile

from evidenceos.capsule.scc import verify_scc
from evidenceos.cli import build_parser
from evidenceos.safety_case.verified import VerifiedSafetyCaseInput, VerifiedSafetyCasePipeline


def _valid_reality_kernel_inputs() -> dict:
    physhir = {
        "quantities": [
            {"name": "distance", "value": 1.0, "unit": "m", "dimension": "L"}
        ]
    }
    causal = {
        "nodes": [
            {"id": "treat", "role": "treatment", "time": 0},
            {"id": "out", "role": "outcome", "time": 1},
        ],
        "edges": [{"source": "treat", "target": "out"}],
    }
    config = {"alpha": 0.05, "prior": 1.0, "e_value": 20.0, "enable_canary": False}
    return {"physhir": physhir, "causal": causal, "config": config}


def test_verified_safety_case_builds_scc() -> None:
    inputs = VerifiedSafetyCaseInput(
        claim_id="claim-123",
        claim="Claim A is safe under policy P.",
        safety_properties=("policy-p",),
        adversarial_hypotheses=("attack-1",),
        evidence_items=("evidence-a", "evidence-b"),
        physhir=_valid_reality_kernel_inputs()["physhir"],
        causal=_valid_reality_kernel_inputs()["causal"],
        reality_config=_valid_reality_kernel_inputs()["config"],
        e_value=20.0,
        alpha=0.05,
        prior=1.0,
        resource_cost=0.2,
        build_utc="2026-01-21T00:00:00Z",
    )
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "scc"
        pipeline = VerifiedSafetyCasePipeline()
        output = pipeline.run(inputs, out_dir)
        assert output.decision_trace.status == "Supported"
        verify_scc(out_dir)


def test_verified_safety_case_reality_kernel_fail_closed() -> None:
    inputs = VerifiedSafetyCaseInput(
        claim_id="claim-124",
        claim="Claim B is safe under policy Q.",
        safety_properties=("policy-q",),
        adversarial_hypotheses=(),
        evidence_items=(),
        physhir={
            "quantities": [
                {"name": "distance", "value": 1.0, "unit": "m", "dimension": "M"}
            ]
        },
        causal=_valid_reality_kernel_inputs()["causal"],
        reality_config=_valid_reality_kernel_inputs()["config"],
        e_value=20.0,
        alpha=0.05,
        prior=1.0,
        resource_cost=0.2,
        build_utc="2026-01-21T00:00:00Z",
    )
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "scc"
        pipeline = VerifiedSafetyCasePipeline()
        output = pipeline.run(inputs, out_dir)
        assert output.decision_trace.status == "Invalid"
        verify_scc(out_dir)


def test_uvp_cli_certify() -> None:
    payload = {
        "claim_id": "claim-cli",
        "claim": "Claim C is safe under policy R.",
        "safety_properties": ["policy-r"],
        "adversarial_hypotheses": ["attack-cli"],
        "evidence_items": ["evidence-cli"],
        "reality_kernel": _valid_reality_kernel_inputs(),
        "e_value": 20.0,
        "alpha": 0.05,
        "prior": 1.0,
        "resource_cost": 0.1,
        "build_utc": "2026-01-21T00:00:00Z",
    }
    with tempfile.TemporaryDirectory() as tmp:
        input_path = Path(tmp) / "input.json"
        out_dir = Path(tmp) / "out"
        input_path.write_text(json.dumps(payload), encoding="utf-8")
        parser = build_parser()
        args = parser.parse_args(
            ["uvp", "certify", "--input", str(input_path), "--out-dir", str(out_dir)]
        )
        rc = args.func(args)
        assert rc == 0
        verify_scc(out_dir)
