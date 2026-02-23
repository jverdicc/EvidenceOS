from __future__ import annotations

from pathlib import Path

from kernel.io_schema import load_json
from kernel.subprocess_utils import run_checked


def run(repo_root: Path, quick: bool) -> dict[str, bool]:
    fixtures_root = repo_root / 'artifacts' / 'forc10' / 'original_python' / 'inputs'
    if not quick:
        run_checked(
            [
                'cargo',
                'test',
                '-p',
                'evidenceos-daemon',
                '--test',
                'probing_detection_system',
                '--',
                '--nocapture',
            ],
            cwd=repo_root,
        )

    summary_path = (
        fixtures_root / 'probing_detection_system.json'
        if quick
        else repo_root / 'artifacts' / 'probing' / 'probing_detection_system.json'
    )
    summary = load_json(summary_path)
    return {
        'probe_saw_throttle': bool(summary['saw_throttle']),
        'probe_saw_freeze': bool(summary['saw_freeze']),
    }
