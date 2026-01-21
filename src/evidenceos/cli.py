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

    uvp = sub.add_parser("uvp", help="UVP verified safety case tooling")
    uvp_sub = uvp.add_subparsers(dest="uvp_cmd", required=True)
    uvp_sc = uvp_sub.add_parser("safety-case", help="Run Verified Safety Case batch")
    uvp_sc.add_argument("--session-dir", required=True)
    uvp_sc.add_argument("--safety-property", required=True)
    uvp_sc.add_argument("--hypotheses", required=True)
    uvp_sc.add_argument("--kernel-private-key", required=True)
    uvp_sc.add_argument("--timestamp-utc", required=True)
    uvp_sc.set_defaults(func=_cmd_uvp_safety_case)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    rc = args.func(args)
    raise SystemExit(rc)
