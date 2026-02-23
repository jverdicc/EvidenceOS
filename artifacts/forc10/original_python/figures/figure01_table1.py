from __future__ import annotations

import csv
from pathlib import Path


def render(out_dir: Path, metrics: dict[str, object]) -> None:
    fig_dir = out_dir / 'figures'
    fig_dir.mkdir(parents=True, exist_ok=True)

    rows = [
        ('Scenario tests (total)', metrics['scenario_total']),
        ('Scenario tests (passed)', metrics['scenario_passed']),
        ('Scenario tests (failed)', metrics['scenario_failed']),
        ('Probe detector throttled', str(metrics['probe_saw_throttle']).lower()),
        ('Probe detector froze', str(metrics['probe_saw_freeze']).lower()),
    ]

    with (fig_dir / 'table_1.csv').open('w', newline='', encoding='utf-8') as handle:
        writer = csv.writer(handle)
        writer.writerow(['result', 'value'])
        writer.writerows(rows)

    lines = ['# FORC10 Reproduction Table', '', '| Result | Value |', '|---|---:|']
    for label, value in rows:
        lines.append(f'| {label} | {value} |')
    (fig_dir / 'table_1.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
