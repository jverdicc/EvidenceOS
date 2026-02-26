#!/usr/bin/env python3
"""Implementation status guardrails for truth-in-advertising CI gates."""

from __future__ import annotations

from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_RS = REPO_ROOT / "crates" / "evidenceos-daemon" / "src" / "server.rs"
SERVER_MOD_RS = REPO_ROOT / "crates" / "evidenceos-daemon" / "src" / "server" / "mod.rs"


class GuardFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise GuardFailure(message)


def load_daemon_server_sources() -> str:
    if SERVER_RS.exists():
        return SERVER_RS.read_text(encoding="utf-8")

    if SERVER_MOD_RS.exists():
        server_dir = SERVER_MOD_RS.parent
        parts = [
            path.read_text(encoding="utf-8")
            for path in sorted(server_dir.rglob("*.rs"))
        ]
        return "\n".join(parts)

    fail(
        "could not locate daemon server sources at "
        "crates/evidenceos-daemon/src/server.rs or crates/evidenceos-daemon/src/server/mod.rs"
    )


def extract_function_body(server_src: str, function_name: str) -> str:
    fn_start = server_src.find(f"fn {function_name}")
    if fn_start == -1:
        fail(f"could not locate {function_name} implementation")

    body_start = server_src.find("{", fn_start)
    if body_start == -1:
        fail(f"could not parse {function_name} body start")

    brace_depth = 0
    for idx in range(body_start, len(server_src)):
        char = server_src[idx]
        if char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
            if brace_depth == 0:
                return server_src[body_start + 1 : idx]

    fail(f"could not parse {function_name} body end")


def check_oracle_signature_verification(server_src: str) -> None:
    body = extract_function_body(server_src, "verify_signed_oracle_record")
    if ".verify_strict(" not in body:
        fail("verify_signed_oracle_record must perform strict ed25519 signature verification")


def check_forbidden_zeroed_dp_accounting() -> None:
    rust_files = list((REPO_ROOT / "crates").rglob("*.rs"))
    pattern = re.compile(r"\*\s*0\.0")
    comment_pattern = re.compile(r"//.*?$|/\*.*?\*/", re.MULTILINE | re.DOTALL)
    offenders: list[Path] = []
    for path in rust_files:
        src = path.read_text(encoding="utf-8")
        src_without_comments = comment_pattern.sub("", src)
        if pattern.search(src_without_comments):
            offenders.append(path)
    if offenders:
        fail("forbidden zeroed DP accounting pattern '* 0.0' found in: " + ", ".join(str(p.relative_to(REPO_ROOT)) for p in offenders))


def check_synthetic_holdout_gate(server_src: str) -> None:
    if "EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT" not in server_src:
        fail("synthetic holdout mode must be explicitly gated by EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT")
    instantiation_pattern = re.compile(r"Arc::new\(\s*SyntheticHoldoutProvider\s*[,)\n]")
    instantiations = list(instantiation_pattern.finditer(server_src))
    if not instantiations:
        fail("synthetic holdout provider must only be enabled via explicit insecure mode")

    marker = "EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT"
    window_chars = 8000
    for match in instantiations:
        window_start = max(0, match.start() - window_chars)
        window = server_src[window_start : match.start()]
        if marker not in window:
            fail(
                "synthetic holdout provider instantiation must be preceded by "
                "EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT gating"
            )


def main() -> int:
    try:
        server_src = load_daemon_server_sources()
        check_oracle_signature_verification(server_src)
        check_forbidden_zeroed_dp_accounting()
        check_synthetic_holdout_gate(server_src)
    except GuardFailure as exc:
        print(f"guard check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
