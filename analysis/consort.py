from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import pandas as pd


CONSORT_STEPS = [
    "screened",
    "eligible",
    "randomized",
    "received_intervention",
    "followup_complete",
    "analyzed",
]


def consort_counts(df: Any) -> dict[str, int]:
    if df.empty:
        return {step: 0 for step in CONSORT_STEPS}

    rank = {step: i for i, step in enumerate(CONSORT_STEPS)}
    max_reached = df["status"].map(lambda x: rank.get(str(x), rank["randomized"]))
    out: dict[str, int] = {}
    for step, idx in rank.items():
        out[step] = int((max_reached >= idx).sum())
    return out


def to_dot(counts: dict[str, int]) -> str:
    lines = [
        "digraph consort {",
        "  rankdir=TB;",
        '  node [shape=box, style="rounded,filled", color="#2d5", fillcolor="#eef"];',
    ]
    for step in CONSORT_STEPS:
        lines.append(f'  {step} [label="{step.replace("_", " ")}\\nN={counts.get(step, 0)}"];')
    for cur, nxt in zip(CONSORT_STEPS, CONSORT_STEPS[1:]):
        lines.append(f"  {cur} -> {nxt};")
    lines.append("}")
    return "\n".join(lines)


def write_consort_diagram(df: Any, out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    counts = consort_counts(df)
    dot_path = out / "consort.dot"
    dot_path.write_text(to_dot(counts), encoding="utf-8")

    try:
        import graphviz

        src = graphviz.Source(dot_path.read_text(encoding="utf-8"))
        src.render(filename="consort", directory=str(out), format="png", cleanup=True)
    except Exception:
        # graphviz is optional; keep DOT output as the canonical artifact
        pass

    return dot_path
