from pathlib import Path
import tempfile

from evidenceos.capsule.claim_capsule import ClaimCapsuleBuilder, verify_capsule

def test_capsule_build_and_verify() -> None:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "caps"
        b = ClaimCapsuleBuilder()
        root = b.build(
            p,
            contract={"a": 1},
            transcript={"events": [1,2]},
            global_ledger={"g": True},
            decision_trace={"status": "Supported"},
            build_utc="2026-01-21T00:00:00Z",
        )
        assert root.startswith("sha256:")
        verify_capsule(p)

def test_capsule_tamper_detected() -> None:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "caps"
        b = ClaimCapsuleBuilder()
        b.build(
            p,
            contract={"a": 1},
            transcript={"events": [1,2]},
            global_ledger={"g": True},
            decision_trace={"status": "Supported"},
            build_utc="2026-01-21T00:00:00Z",
        )
        # tamper contract.json
        (p / "contract.json").write_text("{\"a\":999}", encoding="utf-8")
        try:
            verify_capsule(p)
            assert False, "expected failure"
        except RuntimeError:
            pass
