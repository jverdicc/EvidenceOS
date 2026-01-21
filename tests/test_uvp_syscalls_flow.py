from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from evidenceos.common.signing import Ed25519Keypair, verify_ed25519
from evidenceos.uvp import (
    init_session_dir,
    scc_payload_for_verify,
    uvp_announce,
    uvp_certify,
    uvp_evaluate,
    uvp_propose,
)
from evidenceos.uvp.session_store import read_json, session_paths


def _manifest(require_physhir: bool = True, require_causal: bool = True) -> dict:
    return {
        "manifest_id": "pds-1",
        "reality_gates": {
            "require_physhir": require_physhir,
            "require_causal_dag": require_causal,
            "require_canary": False,
        },
        "ewl_policy": {
            "null_p": 0.4,
            "alt_p": 0.6,
            "initial_wealth": 1.0,
            "bankruptcy_floor": 0.0,
        },
    }


def _physhir_valid() -> dict:
    return {
        "target": {"name": "force", "units": "kg*m/s^2"},
        "variables": [
            {"name": "mass", "units": "kg"},
            {"name": "accel", "units": "m/s^2"},
        ],
        "expression": {
            "type": "Mul",
            "lhs": {"type": "Var", "name": "mass"},
            "rhs": {"type": "Var", "name": "accel"},
        },
        "observations": {"mass": 1.0, "accel": 2.0, "force": 2.0},
        "constraints": {
            "pinned_primaries": [
                {"name": "mass", "units": "kg", "value": 1.0, "locked": True}
            ],
            "ranges": [{"var": "accel", "min": 0.0, "max": 10.0, "units": "m/s^2"}],
            "conservation": [
                {
                    "kind": "force_balance",
                    "inputs": ["force"],
                    "outputs": ["force"],
                    "tolerance": 0.0,
                    "units": "kg*m/s^2",
                }
            ],
        },
    }


def _physhir_invalid() -> dict:
    return {
        "target": {"name": "mass", "units": "m"},
        "variables": [{"name": "mass", "units": "kg"}],
        "expression": {"type": "Var", "name": "mass"},
    }


def _causal_dag() -> dict:
    return {
        "nodes": [
            {"id": "T", "time_index": 0},
            {"id": "Y", "time_index": 1},
        ],
        "edges": [{"src": "T", "dst": "Y"}],
        "treatment": "T",
        "outcome": "Y",
        "adjustment_set": [],
    }


def test_uvp_syscalls_flow_certify_signature() -> None:
    with TemporaryDirectory() as tmp:
        session_dir = Path(tmp) / "uvp-session"
        init_session_dir(session_dir)

        uvp_announce(session_dir, _manifest())
        uvp_propose(
            session_dir,
            _causal_dag(),
            _physhir_valid(),
            [{"payload_id": "artifact-1", "hash": "sha256:" + "0" * 64}],
        )
        uvp_evaluate(session_dir, "safety-claim", 1, {"note": "pass"})

        keypair = Ed25519Keypair.generate()
        uvp_certify(session_dir, keypair, "2024-01-01T00:00:00Z")

        scc = read_json(session_paths(session_dir).scc_path)
        payload = scc_payload_for_verify(scc)
        signature = scc["signature"]
        public_key_hex = scc["kernel_public_key"].split(":", 1)[1]
        assert verify_ed25519(bytes.fromhex(public_key_hex), payload, signature)


def test_gating_failure_prevents_ewl_update() -> None:
    with TemporaryDirectory() as tmp:
        session_dir = Path(tmp) / "uvp-session"
        init_session_dir(session_dir)

        uvp_announce(session_dir, _manifest(require_causal=False))
        uvp_propose(
            session_dir,
            _causal_dag(),
            _physhir_invalid(),
            [{"payload_id": "artifact-1", "hash": "sha256:" + "0" * 64}],
        )
        ewl_before = read_json(session_paths(session_dir).ewl_state_path)
        uvp_evaluate(session_dir, "safety-claim", 1, {"note": "fail"})
        ewl_after = read_json(session_paths(session_dir).ewl_state_path)

        assert ewl_before["wealth"] == ewl_after["wealth"]
        assert ewl_before["updates"] == ewl_after["updates"]
