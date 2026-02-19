#!/usr/bin/env python3
"""Validate coverage policy consistency against scripts/test_evidence.sh."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SCRIPT = ROOT / "scripts" / "test_evidence.sh"


def parse_source_threshold(script_text: str) -> int:
    match = re.search(r"--fail-under-lines\s+(\d+)", script_text)
    if not match:
        raise ValueError("could not find --fail-under-lines threshold in scripts/test_evidence.sh")
    return int(match.group(1))


def check_contains(pattern: str, content: str, path: Path, expected: int) -> str | None:
    if re.search(pattern.format(expected=expected), content, re.MULTILINE):
        return None
    return f"{path}: expected to match /{pattern.format(expected=expected)}/"


def main() -> int:
    script_text = SOURCE_SCRIPT.read_text(encoding="utf-8")
    threshold = parse_source_threshold(script_text)

    checks = [
        (ROOT / "Makefile", r"^\t\./scripts/test_evidence\.sh$"),
        (ROOT / "docs" / "TEST_EVIDENCE.md", r"\*\*>=\s*{expected}%\*\*"),
        (ROOT / "README.md", r"{expected}% line-coverage gate"),
        (ROOT / "TESTING_EVIDENCE.md", r"--fail-under-lines {expected}"),
    ]

    failures: list[str] = []
    for path, pattern in checks:
        content = path.read_text(encoding="utf-8")
        err = check_contains(pattern, content, path.relative_to(ROOT), threshold)
        if err:
            failures.append(err)

    if failures:
        print("Coverage policy mismatch detected:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(f"Coverage policy consistency check passed (threshold: {threshold}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
