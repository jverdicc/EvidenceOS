#!/usr/bin/env python3
"""Implementation status guardrails for truth-in-advertising CI gates.

Paper-critical invariants enforced by this guard (fail-closed):
1) Oracle signature verification MUST be strict in server-side oracle record
   verification (`verify_strict(...)`, never permissive checks).
2) Synthetic holdout is an insecure/dev-only mode and MUST be gated behind an
   explicit opt-in environment variable
   (`EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT`) rather than production defaults.
3) DP lane accounting MUST NOT be zeroed out to silently bypass privacy
   accounting when DP-related code paths are enabled.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
DAEMON_SRC = REPO_ROOT / "crates" / "evidenceos-daemon" / "src"


class GuardFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise GuardFailure(message)


def discover_daemon_server_sources() -> list[Path]:
    sources: list[Path] = []
    legacy_server_rs = DAEMON_SRC / "server.rs"
    server_dir = DAEMON_SRC / "server"

    if legacy_server_rs.exists():
        sources.append(legacy_server_rs)

    if server_dir.exists():
        sources.extend(sorted(server_dir.rglob("*.rs")))

    if sources:
        return sources

    fail(
        "could not locate daemon server sources at "
        "crates/evidenceos-daemon/src/server.rs or crates/evidenceos-daemon/src/server/*.rs"
    )


def format_search_paths(paths: list[Path]) -> str:
    return ", ".join(str(path.relative_to(REPO_ROOT)) for path in paths)


def resolve_searched_files(searched_files: list[Path] | None) -> list[Path]:
    if searched_files is None:
        return [REPO_ROOT / Path("scripts/tests/__unit_test_fixture__.rs")]
    return searched_files


def load_daemon_server_sources() -> tuple[str, list[Path]]:
    source_paths = discover_daemon_server_sources()
    parts = [path.read_text(encoding="utf-8") for path in source_paths]
    return "\n".join(parts), source_paths


def fail_missing_symbol(symbol: str, searched_files: list[Path]) -> None:
    fail(
        f"missing required symbol: {symbol}; "
        f"searched files: {format_search_paths(searched_files)}"
    )


def extract_fn_body(source: str, fn_name: str) -> str:
    """Extract the body for `fn <fn_name>` using brace matching."""
    fn_start = source.find(f"fn {fn_name}")
    if fn_start == -1:
        raise ValueError(f"missing fn {fn_name}")

    body_start = source.find("{", fn_start)
    if body_start == -1:
        raise ValueError(f"could not parse {fn_name} body start")

    brace_depth = 0
    for idx in range(body_start, len(source)):
        char = source[idx]
        if char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
            if brace_depth == 0:
                return source[body_start + 1 : idx]

    raise ValueError(f"could not parse {fn_name} body end")


def extract_function_body(server_src: str, function_name: str, searched_files: list[Path]) -> str:
    try:
        return extract_fn_body(server_src, function_name)
    except ValueError as exc:
        if str(exc).startswith("missing fn"):
            fail_missing_symbol(f"fn {function_name}", searched_files)
        fail(str(exc))


def _find_env_gated_spans(server_src: str, marker: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    scan_idx = 0
    while True:
        marker_idx = server_src.find(marker, scan_idx)
        if marker_idx == -1:
            return spans

        block_start = server_src.find("{", marker_idx)
        if block_start == -1:
            scan_idx = marker_idx + len(marker)
            continue

        depth = 0
        block_end = -1
        for idx in range(block_start, len(server_src)):
            ch = server_src[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    block_end = idx
                    break

        if block_end != -1:
            spans.append((block_start, block_end))
            scan_idx = block_end + 1
        else:
            scan_idx = block_start + 1


def check_oracle_signature_verification(
    server_src: str, searched_files: list[Path] | None = None
) -> None:
    searched_files = resolve_searched_files(searched_files)
    body = extract_function_body(server_src, "verify_signed_oracle_record", searched_files)
    normalized = re.sub(r"\s+", "", body)
    if "verify_strict(" not in normalized:
        fail("verify_signed_oracle_record must perform strict ed25519 signature verification")


def check_signature_guards(server_src: str, searched_files: list[Path]) -> None:
    check_oracle_signature_verification(server_src, searched_files)
    extract_function_body(server_src, "verify_epoch_control_record", searched_files)


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


def check_synthetic_holdout_gate(
    server_src: str, searched_files: list[Path] | None = None
) -> None:
    explicit_search_paths = searched_files is not None
    searched_files = resolve_searched_files(searched_files)
    if explicit_search_paths and "fn derive_holdout_labels" not in server_src:
        fail_missing_symbol("fn derive_holdout_labels", searched_files)

    derive_holdout_labels_calls = re.findall(r"(?<!fn\s)derive_holdout_labels\s*\(", server_src)
    if explicit_search_paths and not derive_holdout_labels_calls:
        fail_missing_symbol("derive_holdout_labels(...) call site", searched_files)

    if "EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT" not in server_src:
        fail_missing_symbol("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT", searched_files)

    instantiation_pattern = re.compile(r"Arc::new\(\s*SyntheticHoldoutProvider\s*[,)\n]")
    instantiations = list(instantiation_pattern.finditer(server_src))
    if not instantiations:
        fail_missing_symbol("Arc::new(SyntheticHoldoutProvider)", searched_files)

    marker = "EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT"
    gated_spans = _find_env_gated_spans(server_src, marker)
    if not gated_spans:
        fail(
            "could not locate a parseable block gated by "
            "EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT"
        )

    for match in instantiations:
        pos = match.start()
        if not any(start <= pos <= end for start, end in gated_spans):
            fail(
                "synthetic holdout provider instantiation must be preceded by "
                "EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT gating"
            )


def check_quantized_hysteresis_credit_line(
    server_src: str, searched_files: list[Path] | None = None
) -> None:
    searched_files = resolve_searched_files(searched_files)
    if "padded_fuel_total" not in server_src:
        fail_missing_symbol("padded_fuel_total", searched_files)


def main() -> int:
    try:
        server_src, searched_files = load_daemon_server_sources()
        check_signature_guards(server_src, searched_files)
        check_forbidden_zeroed_dp_accounting()
        check_synthetic_holdout_gate(server_src, searched_files)
        check_quantized_hysteresis_credit_line(server_src, searched_files)
    except GuardFailure as exc:
        print(f"guard check failed: {exc}", file=sys.stderr)
        return 1

    print("guard check passed")
    print("self-check:")
    for path in searched_files:
        print(f" - {path.relative_to(REPO_ROOT)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
