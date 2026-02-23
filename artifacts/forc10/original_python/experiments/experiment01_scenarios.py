from __future__ import annotations

from pathlib import Path

from kernel.io_schema import load_json
from kernel.subprocess_utils import run_checked


def run(repo_root: Path, quick: bool) -> dict[str, int]:
    fixtures_root = repo_root / 'artifacts' / 'forc10' / 'original_python' / 'inputs'
    if not quick:
        run_checked(
            [
                'cargo',
                'test',
                '-p',
                'evidenceos-daemon',
                '--test',
                'scenarios_system',
                '--',
                '--nocapture',
            ],
            cwd=repo_root,
        )

    summary_path = (
        fixtures_root / 'scenarios_summary.json'
        if quick
        else repo_root / 'artifacts' / 'scenarios' / 'summary.json'
    )
    summary = load_json(summary_path)
    totals = summary['totals']
    return {
        'scenario_total': int(totals['total']),
        'scenario_passed': int(totals['passed']),
        'scenario_failed': int(totals['failed']),
    }
