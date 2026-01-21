from __future__ import annotations

import json
from pathlib import Path

from evidenceos.common.signing import Ed25519Keypair
from evidenceos.uvp.safety_case import AdversarialHypothesis, SafetyCaseRunner


def _write_config(
    session_dir: Path,
    *,
    alpha: float,
    prior: float,
    p0: float,
    p1: float,
    bankruptcy_threshold: float | None = None,
    enable_reality_kernel: bool = False,
) -> None:
    payload = {
        "alpha": alpha,
        "prior": prior,
        "p0": p0,
        "p1": p1,
        "enable_reality_kernel": enable_reality_kernel,
    }
    if bankruptcy_threshold is not None:
        payload["bankruptcy_threshold"] = bankruptcy_threshold
    (session_dir / "uvp_config.json").write_text(json.dumps(payload), encoding="utf-8")


def _write_reality_kernel_invalid(session_dir: Path) -> None:
    rk_dir = session_dir / "reality_kernel"
    rk_dir.mkdir(parents=True, exist_ok=True)
    physhir = {
        "quantities": [{"name": "length", "value": 1.0, "unit": "m", "dimension": "L"}]
    }
    causal = {
        "nodes": [
            {"id": "treat", "role": "treatment", "time": 0},
            {"id": "out", "role": "outcome", "time": 1},
        ],
        "edges": [{"source": "treat", "target": "out"}],
    }
    config = {"alpha": 0.1, "prior": 1.0, "e_value": 1.0, "enable_canary": True}
    (rk_dir / "physhir.json").write_text(json.dumps(physhir), encoding="utf-8")
    (rk_dir / "causal.json").write_text(json.dumps(causal), encoding="utf-8")
    (rk_dir / "config.json").write_text(json.dumps(config), encoding="utf-8")


def test_safety_case_supports_when_passes(tmp_path: Path) -> None:
    session_dir = tmp_path / "session_support"
    session_dir.mkdir(parents=True, exist_ok=True)
    _write_config(session_dir, alpha=0.2, prior=1.0, p0=0.5, p1=0.1)

    hypotheses = [
        AdversarialHypothesis(hypothesis_id="h1", attack_description="attack A"),
        AdversarialHypothesis(hypothesis_id="h2", attack_description="attack B"),
        AdversarialHypothesis(hypothesis_id="h3", attack_description="attack C"),
    ]

    def evaluator(_: AdversarialHypothesis) -> int:
        return 0

    runner = SafetyCaseRunner()
    scc = runner.run(
        session_dir=session_dir,
        safety_property="policy:no_unsafe_output",
        hypotheses=hypotheses,
        evaluator=evaluator,
        kernel_keypair=Ed25519Keypair.generate(),
        timestamp_utc="2025-01-01T00:00:00Z",
    )

    assert scc.decision.status == "SUPPORTED+"
    assert scc.counts.tested == 3
    assert scc.counts.fails == 0


def test_safety_case_bankrupts_on_failures(tmp_path: Path) -> None:
    session_dir = tmp_path / "session_bankrupt"
    session_dir.mkdir(parents=True, exist_ok=True)
    _write_config(session_dir, alpha=0.2, prior=1.0, p0=0.5, p1=0.1, bankruptcy_threshold=0.1)

    hypotheses = [
        AdversarialHypothesis(hypothesis_id="h1", attack_description="attack A"),
        AdversarialHypothesis(hypothesis_id="h2", attack_description="attack B"),
        AdversarialHypothesis(hypothesis_id="h3", attack_description="attack C"),
    ]

    def evaluator(_: AdversarialHypothesis) -> int:
        return 1

    runner = SafetyCaseRunner()
    scc = runner.run(
        session_dir=session_dir,
        safety_property="policy:no_unsafe_output",
        hypotheses=hypotheses,
        evaluator=evaluator,
        kernel_keypair=Ed25519Keypair.generate(),
        timestamp_utc="2025-01-01T00:00:00Z",
    )

    assert scc.decision.status == "BANKRUPT"
    assert scc.counts.tested == 2
    assert scc.counts.fails == 2


def test_gated_out_hypotheses_do_not_affect_wealth(tmp_path: Path) -> None:
    session_dir = tmp_path / "session_gate"
    session_dir.mkdir(parents=True, exist_ok=True)
    _write_config(
        session_dir,
        alpha=0.2,
        prior=1.0,
        p0=0.5,
        p1=0.1,
        enable_reality_kernel=True,
    )
    _write_reality_kernel_invalid(session_dir)

    hypotheses = [
        AdversarialHypothesis(hypothesis_id="h1", attack_description="attack A"),
        AdversarialHypothesis(hypothesis_id="h2", attack_description="attack B"),
    ]

    def evaluator(_: AdversarialHypothesis) -> int:
        return 1

    runner = SafetyCaseRunner()
    scc = runner.run(
        session_dir=session_dir,
        safety_property="policy:no_unsafe_output",
        hypotheses=hypotheses,
        evaluator=evaluator,
        kernel_keypair=Ed25519Keypair.generate(),
        timestamp_utc="2025-01-01T00:00:00Z",
    )

    assert scc.decision.status == "Invalid"
    assert scc.counts.gated_out == 2
    assert scc.ewl["e_value"] == 1.0
