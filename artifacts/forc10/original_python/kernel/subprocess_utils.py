from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Mapping, Sequence


def run_checked(cmd: Sequence[str], cwd: Path, env: Mapping[str, str] | None = None) -> None:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    subprocess.run(cmd, cwd=cwd, check=True, env=merged_env)
