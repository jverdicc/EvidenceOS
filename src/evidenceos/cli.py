# Copyright 2026 Joseph Verdicchio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evidenceos.admissibility.reality_kernel import RealityKernel
from evidenceos.capsule.claim_capsule import verify_capsule
from evidenceos.common.signing import Ed25519Keypair
from evidenceos.etl.store_file import EvidenceTransparencyLog
from evidenceos.uvp.safety_case import (
    AdversarialHypothesis,
    SafetyCaseRunner,
    load_hypotheses_batch_with_outcomes,
    render_scc_json,
)
from evidenceos.common.schema_validate import validate_json
from evidenceos.etl.store_file import EvidenceTransparencyLog
from evidenceos.uvp import (
    init_session_dir,
    keypair_from_private_hex,
    uvp_announce,
    uvp_certify,
    uvp_evaluate,
    uvp_propose,
)
from evidenceos.safety_case.verified import VerifiedSafetyCaseInput, VerifiedSafetyCasePipeline
from evidenceos.ledger.ledger import ConservationLedger
from evidenceos.schemas.popperpp import FalsificationConfig
from evidenceos.teams.popperpp.team import PopperppTeam
from evidenceos.teams.popperpp.types import ClaimContract, DataContract


def _cmd_capsule_verify(args: argparse.Namespace) -> int:
    verify_capsule(Path(args.capsule_dir))
    print("OK: capsule verified")
    return 0


def _cmd_etl_init(args: argparse.Namespace) -> int:
    EvidenceTransparencyLog.init(Path(args.log_dir))
    print("OK: ETL initialized")
    return 0


def _cmd_etl_append(args: argparse.Namespace) -> int:
    log = EvidenceTransparencyLog(Path(args.log_dir))
    meta = json.loads(args.meta) if args.meta else {}
    entry_hash, sth = log.append({"capsule_root": args.capsule_root, **meta})
    print(entry_hash)
    print(json.dumps(sth, indent=2, sort_keys=True))
    return 0


def _cmd_etl_verify(args: argparse.Namespace) -> int:
    log = EvidenceTransparencyLog(Path(args.log_dir))
    ok = log.verify_inclusion(args.entry_hash)
    if not ok:
        raise SystemExit("ETL inclusion verification failed")
    print("OK: ETL inclusion verified")
    return 0


def _cmd_reality_validate(args: argparse.Namespace) -> int:
    kernel = RealityKernel()
    result = kernel.validate_from_files(
        Path(args.physhir),
        Path(args.causal),
        Path(args.config),
    )
    if result.ok:
        print("PASS")
        return 0
    print(result.errors[0].code)
    return 1


def _load_ed25519_keypair(path: Path) -> Ed25519Keypair:
    key_hex = path.read_text(encoding="utf-8").strip()
    key_bytes = bytes.fromhex(key_hex)
    if len(key_bytes) != 32:
        raise ValueError("ed25519_private_key_must_be_32_bytes")
    private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
    return Ed25519Keypair(private_key=private_key, public_key=private_key.public_key())


def _cmd_uvp_safety_case(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir)
    hypotheses, outcomes = load_hypotheses_batch_with_outcomes(Path(args.hypotheses))
    keypair = _load_ed25519_keypair(Path(args.kernel_private_key))

    def evaluator(hypothesis: AdversarialHypothesis) -> int:
        if hypothesis.hypothesis_id not in outcomes:
            raise ValueError("missing_outcome")
        return outcomes[hypothesis.hypothesis_id]

    runner = SafetyCaseRunner()
    scc = runner.run(
        session_dir=session_dir,
        safety_property=str(args.safety_property),
        hypotheses=hypotheses,
        evaluator=evaluator,
        kernel_keypair=keypair,
        timestamp_utc=str(args.timestamp_utc),
    )
    print(render_scc_json(scc))


def _cmd_falsify(args: argparse.Namespace) -> int:
    claim_payload = _load_json_object(Path(args.claim))
    data_payload = _load_json_object(Path(args.data))
    config_payload = _load_json_object(Path(args.config))
    config = FalsificationConfig.model_validate(config_payload)
    if args.lane:
        config.lane_policy = {**config.lane_policy, "default": args.lane}

    claim = ClaimContract(
        claim_id=str(claim_payload.get("claim_id", "claim-unknown")),
        dataset_id=str(claim_payload.get("dataset_id", "dataset-unknown")),
        null_nl=str(claim_payload.get("null_nl", "null")),
        alt_nl=str(claim_payload.get("alt_nl", "alt")),
    )
    data_contract = DataContract(
        dataset_id=str(data_payload.get("dataset_id", claim.dataset_id)),
        allowed_columns=list(data_payload.get("allowed_columns", [])),
    )
    ledger = ConservationLedger()
    team = PopperppTeam(config)
    run = team.run(claim, data_contract, ledger)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_path = out_dir / "falsification_run.json"
    ledger_path = out_dir / "ledger_snapshot.json"
    run_path.write_text(run.model_dump_json(indent=2), encoding="utf-8")
    ledger_path.write_text(
        json.dumps(run.ledger_snapshot.model_dump(), indent=2), encoding="utf-8"
    )
    print(run_path)
    return 0
def _load_json_file(path: Path) -> object:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _load_json_object(path: Path) -> dict:
    payload = _load_json_file(path)
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    return payload


def _cmd_uvp_init(args: argparse.Namespace) -> int:
    init_session_dir(Path(args.session_dir))
    print("OK: UVP session initialized")
    return 0


def _cmd_uvp_announce(args: argparse.Namespace) -> int:
    manifest = _load_json_object(Path(args.manifest))
    uvp_announce(Path(args.session_dir), manifest)
    print("OK: UVP announce stored")
    return 0


def _cmd_uvp_propose(args: argparse.Namespace) -> int:
    causal = _load_json_object(Path(args.causal))
    physhir = _load_json_object(Path(args.physhir))
    payload_hashes = _load_json_file(Path(args.payload_hashes))
    if not isinstance(payload_hashes, list):
        raise ValueError("payload_hashes must be a JSON array")
    uvp_propose(Path(args.session_dir), causal, physhir, payload_hashes)
    print("OK: UVP propose stored")
    return 0


def _cmd_uvp_evaluate(args: argparse.Namespace) -> int:
    meta = json.loads(args.meta) if args.meta else {}
    entry = uvp_evaluate(Path(args.session_dir), args.hypothesis, int(args.outcome_x), meta)
    print(json.dumps(entry, sort_keys=True, indent=2))
    return 0


def _cmd_uvp_certify(args: argparse.Namespace) -> int:
    keypair = keypair_from_private_hex(args.kernel_private_key_hex)
    uvp_certify(Path(args.session_dir), keypair, args.timestamp_utc)
def _cmd_uvp_certify(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    schema_path = (
        Path(__file__).resolve().parents[0]
        / "schemas"
        / "uvp"
        / "safety_case_request.schema.json"
    )
    validate_json(payload, schema_path)
    inputs = VerifiedSafetyCaseInput.from_payload(payload)
    pipeline = VerifiedSafetyCasePipeline()
    pipeline.run(inputs, Path(args.out_dir))
    print("OK: SCC generated")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="evidenceos")
    sub = p.add_subparsers(dest="cmd", required=True)

    cap = sub.add_parser("capsule", help="Capsule utilities")
    cap_sub = cap.add_subparsers(dest="cap_cmd", required=True)
    cap_v = cap_sub.add_parser("verify", help="Verify a capsule directory")
    cap_v.add_argument("capsule_dir")
    cap_v.set_defaults(func=_cmd_capsule_verify)

    etl = sub.add_parser("etl", help="Transparency log utilities")
    etl_sub = etl.add_subparsers(dest="etl_cmd", required=True)

    etl_i = etl_sub.add_parser("init", help="Initialize ETL directory")
    etl_i.add_argument("log_dir")
    etl_i.set_defaults(func=_cmd_etl_init)

    etl_a = etl_sub.add_parser("append", help="Append entry to ETL")
    etl_a.add_argument("log_dir")
    etl_a.add_argument("capsule_root")
    etl_a.add_argument("--meta", default="", help="JSON string metadata")
    etl_a.set_defaults(func=_cmd_etl_append)

    etl_v = etl_sub.add_parser("verify", help="Verify inclusion of entry_hash in ETL")
    etl_v.add_argument("log_dir")
    etl_v.add_argument("entry_hash")
    etl_v.set_defaults(func=_cmd_etl_verify)

    reality = sub.add_parser("reality", help="Reality Kernel gates")
    reality_sub = reality.add_subparsers(dest="reality_cmd", required=True)
    reality_validate = reality_sub.add_parser("validate", help="Validate Reality Kernel inputs")
    reality_validate.add_argument("--physhir", required=True)
    reality_validate.add_argument("--causal", required=True)
    reality_validate.add_argument("--config", required=True)
    reality_validate.set_defaults(func=_cmd_reality_validate)

    falsify = sub.add_parser("falsify", help="Run POPPER++ falsification protocol")
    falsify.add_argument("--claim", required=True)
    falsify.add_argument("--data", required=True)
    falsify.add_argument("--config", required=True)
    falsify.add_argument("--lane", default=None, help="Override default lane policy")
    falsify.add_argument("--out-dir", required=True)
    falsify.set_defaults(func=_cmd_falsify)

    uvp = sub.add_parser("uvp", help="UVP verified safety case tooling")
    uvp_sub = uvp.add_subparsers(dest="uvp_cmd", required=True)
    uvp_sc = uvp_sub.add_parser("safety-case", help="Run Verified Safety Case batch")
    uvp_sc.add_argument("--session-dir", required=True)
    uvp_sc.add_argument("--safety-property", required=True)
    uvp_sc.add_argument("--hypotheses", required=True)
    uvp_sc.add_argument("--kernel-private-key", required=True)
    uvp_sc.add_argument("--timestamp-utc", required=True)
    uvp_sc.set_defaults(func=_cmd_uvp_safety_case)
    uvp = sub.add_parser("uvp", help="UVP session syscalls")
    uvp_sub = uvp.add_subparsers(dest="uvp_cmd", required=True)

    uvp_init = uvp_sub.add_parser("init", help="Initialize UVP session directory")
    uvp_init.add_argument("session_dir")
    uvp_init.set_defaults(func=_cmd_uvp_init)

    uvp_announce_cmd = uvp_sub.add_parser("announce", help="Write UVP announce.json")
    uvp_announce_cmd.add_argument("session_dir")
    uvp_announce_cmd.add_argument("--manifest", required=True, help="Path to PDS manifest JSON")
    uvp_announce_cmd.set_defaults(func=_cmd_uvp_announce)

    uvp_propose_cmd = uvp_sub.add_parser("propose", help="Write UVP propose.json")
    uvp_propose_cmd.add_argument("session_dir")
    uvp_propose_cmd.add_argument("--causal", required=True, help="Path to causal DAG JSON")
    uvp_propose_cmd.add_argument("--physhir", required=True, help="Path to PhysHIR JSON")
    uvp_propose_cmd.add_argument(
        "--payload-hashes", required=True, help="Path to payload hashes JSON array"
    )
    uvp_propose_cmd.set_defaults(func=_cmd_uvp_propose)

    uvp_evaluate_cmd = uvp_sub.add_parser("evaluate", help="Append UVP evaluation entry")
    uvp_evaluate_cmd.add_argument("session_dir")
    uvp_evaluate_cmd.add_argument("hypothesis")
    uvp_evaluate_cmd.add_argument("outcome_x")
    uvp_evaluate_cmd.add_argument("--meta", default="", help="JSON string metadata")
    uvp_evaluate_cmd.set_defaults(func=_cmd_uvp_evaluate)

    uvp_certify_cmd = uvp_sub.add_parser("certify", help="Generate SCC and signature")
    uvp_certify_cmd.add_argument("session_dir")
    uvp_certify_cmd.add_argument("--kernel-private-key-hex", required=True)
    uvp_certify_cmd.add_argument("--timestamp-utc", required=True)
    uvp_certify_cmd.set_defaults(func=_cmd_uvp_certify)
    uvp = sub.add_parser("uvp", help="UVP utilities")
    uvp_sub = uvp.add_subparsers(dest="uvp_cmd", required=True)
    uvp_cert = uvp_sub.add_parser("certify", help="Run Verified Safety Case pipeline")
    uvp_cert.add_argument("--input", required=True)
    uvp_cert.add_argument("--out-dir", required=True)
    uvp_cert.set_defaults(func=_cmd_uvp_certify)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    rc = args.func(args)
    raise SystemExit(rc)
