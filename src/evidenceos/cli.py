from __future__ import annotations

import argparse
import json
from pathlib import Path

from evidenceos.capsule.claim_capsule import verify_capsule
from evidenceos.etl.store_file import EvidenceTransparencyLog


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

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    rc = args.func(args)
    raise SystemExit(rc)
