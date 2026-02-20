#!/usr/bin/env python3
"""Render a sanitized blackbox transcript into a markdown report."""

from __future__ import annotations

import json
import math
from pathlib import Path


INPUT_PATH = Path("examples/blackbox_demo/transcript_sanitized.json")
OUTPUT_PATH = Path("docs/generated/blackbox_demo.md")


def load_transcript(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("transcript root must be an object")

    required = {"demo_name", "k_budget_bits", "calls"}
    missing = required.difference(data)
    if missing:
        raise ValueError(f"missing required top-level fields: {sorted(missing)}")

    calls = data["calls"]
    if not isinstance(calls, list) or not calls:
        raise ValueError("calls must be a non-empty array")

    for i, call in enumerate(calls, start=1):
        if not isinstance(call, dict):
            raise ValueError(f"call {i} must be an object")
        for field in ("call_id", "oracle_name", "output_symbol", "alphabet_size"):
            if field not in call:
                raise ValueError(f"call {i} missing field: {field}")

        alphabet_size = call["alphabet_size"]
        if not isinstance(alphabet_size, int) or alphabet_size < 2:
            raise ValueError(f"call {i} has invalid alphabet_size: {alphabet_size!r}")

        for text_field in ("call_id", "oracle_name", "output_symbol"):
            value = call[text_field]
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"call {i} has invalid {text_field}: {value!r}")

    budget = data["k_budget_bits"]
    if not isinstance(budget, (int, float)) or budget <= 0:
        raise ValueError("k_budget_bits must be a positive number")

    return data


def render_report(transcript: dict) -> str:
    calls = transcript["calls"]
    budget = float(transcript["k_budget_bits"])
    cumulative = 0.0
    freeze_at = None

    lines = [
        "# Blackbox Demo: Transcript → Ledger → Freeze",
        "",
        "This report is generated from a precomputed, sanitized transcript.",
        "It demonstrates canonical outputs, k-budget accumulation, and freeze escalation behavior.",
        "",
        f"- Demo: `{transcript['demo_name']}`",
        f"- Configured k budget: `{budget:.2f}` bits",
        "",
        "| Step | call_id | oracle_name | canonical output | alphabet_size | charge Δk (bits) | cumulative k | budget remaining | DiscOS return |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]

    for idx, call in enumerate(calls, start=1):
        delta_k = math.log2(call["alphabet_size"])
        cumulative += delta_k
        remaining = max(0.0, budget - cumulative)

        if freeze_at is None and cumulative >= budget:
            freeze_at = idx

        if freeze_at is not None and idx >= freeze_at:
            discos_return = "`FROZEN` + escalation receipt"
        else:
            discos_return = f"`PASS` canonical `{call['output_symbol']}` + receipt"

        lines.append(
            "| {step} | `{call_id}` | `{oracle}` | `{output}` | {alphabet} | {delta:.2f} | {cum:.2f} | {rem:.2f} | {ret} |".format(
                step=idx,
                call_id=call["call_id"],
                oracle=call["oracle_name"],
                output=call["output_symbol"],
                alphabet=call["alphabet_size"],
                delta=delta_k,
                cum=cumulative,
                rem=remaining,
                ret=discos_return,
            )
        )

    lines.extend(["", "## Outcome", ""])
    if freeze_at is None:
        lines.append("No freeze occurred in this transcript; the budget was not exhausted.")
    else:
        lines.append(
            f"Freeze/escalation begins at step **{freeze_at}** when cumulative `k` reaches the configured budget."
        )

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- This is a defensive demonstration only; it uses abstract symbols and precomputed data.",
            "- No extraction algorithm, optimization loop, or real holdout interaction is included.",
        ]
    )

    return "\n".join(lines) + "\n"


def main() -> None:
    transcript = load_transcript(INPUT_PATH)
    report = render_report(transcript)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(report, encoding="utf-8")
    print(f"wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
