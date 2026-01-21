from __future__ import annotations

import argparse
import json
from pathlib import Path

from evidenceos.admissibility.reality_kernel import RealityKernel
from evidenceos.capsule.claim_capsule import verify_capsule
from evidenceos.common.schema_validate import validate_json
from evidenceos.etl.store_file import EvidenceTransparencyLog
from evidenceos.safety_case.verified import VerifiedSafetyCaseInput, VerifiedSafetyCasePipeline


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
