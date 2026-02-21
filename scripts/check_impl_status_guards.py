#!/usr/bin/env python3
"""Implementation status guardrails for truth-in-advertising CI gates."""

from __future__ import annotations

from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_RS = REPO_ROOT / "crates" / "evidenceos-daemon" / "src" / "server.rs"


class GuardFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise GuardFailure(message)


def check_oracle_signature_verification(server_src: str) -> None:
    match = re.search(
        r"fn\s+verify_signed_oracle_record\s*\([^)]*\)\s*->\s*Result<\(\),\s*Status>\s*\{(?P<body>.*?)\n\}\n\nfn\s+verify_epoch_control_record",
        server_src,
        re.DOTALL,
    )
    if not match:
        fail("could not locate verify_signed_oracle_record implementation")
    body = match.group("body")
    if ".verify_strict(" not in body:
        fail("verify_signed_oracle_record must perform strict ed25519 signature verification")


def check_forbidden_zeroed_dp_accounting() -> None:
    rust_files = list((REPO_ROOT / "crates").rglob("*.rs"))
    pattern = re.compile(r"\*\s*0\.0")
    offenders: list[Path] = []
    for path in rust_files:
        if pattern.search(path.read_text(encoding="utf-8")):
            offenders.append(path)
    if offenders:
        fail("forbidden zeroed DP accounting pattern '* 0.0' found in: " + ", ".join(str(p.relative_to(REPO_ROOT)) for p in offenders))


def check_synthetic_holdout_gate(server_src: str) -> None:
    derive_call_sites = [
        line for line in server_src.splitlines() if "derive_holdout_labels(" in line
    ]
    if len(derive_call_sites) != 3:
        fail(
            "derive_holdout_labels usage changed; expected only function definition + synthetic provider call sites"
        )
    if "EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT" not in server_src:
        fail("synthetic holdout mode must be explicitly gated by EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT")
    if "Arc::new(SyntheticHoldoutProvider)" not in server_src:
        fail("synthetic holdout provider must only be enabled via explicit insecure mode")


def main() -> int:
    try:
        server_src = SERVER_RS.read_text(encoding="utf-8")
        check_oracle_signature_verification(server_src)
        check_forbidden_zeroed_dp_accounting()
        check_synthetic_holdout_gate(server_src)
    except GuardFailure as exc:
        print(f"guard check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
