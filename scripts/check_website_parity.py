#!/usr/bin/env python3
"""Ensure core website parity phrases remain aligned with README messaging."""

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
SNIPPETS = REPO_ROOT / "docs" / "WEBSITE_PARITY_SNIPPETS.md"

KEY_PHRASES = (
    "deterministic settlement kernel",
    "discrete claim capsules",
    "adapter/sidecar for continuous agents",
)


def _load(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"required file not found: {path.relative_to(REPO_ROOT)}")
    return path.read_text(encoding="utf-8")


def _missing_phrases(text: str) -> list[str]:
    lowered = text.lower()
    return [phrase for phrase in KEY_PHRASES if phrase not in lowered]


def main() -> int:
    try:
        readme_text = _load(README)
        snippets_text = _load(SNIPPETS)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    failures: list[str] = []
    readme_missing = _missing_phrases(readme_text)
    snippets_missing = _missing_phrases(snippets_text)

    if readme_missing:
        failures.append(
            "README.md is missing required phrase(s): " + ", ".join(f'"{p}"' for p in readme_missing)
        )
    if snippets_missing:
        failures.append(
            "docs/WEBSITE_PARITY_SNIPPETS.md is missing required phrase(s): "
            + ", ".join(f'"{p}"' for p in snippets_missing)
        )

    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        return 1

    print("website parity phrases present in README.md and docs/WEBSITE_PARITY_SNIPPETS.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
