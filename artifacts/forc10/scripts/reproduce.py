#!/usr/bin/env python3
"""Compatibility wrapper for FORC10 reproduction.

Use artifacts/forc10/original_python/run_all.py directly for the authoritative path.
"""

from pathlib import Path
import subprocess
import sys


if __name__ == '__main__':
    script = Path(__file__).resolve().parents[1] / 'original_python' / 'run_all.py'
    raise SystemExit(subprocess.call([sys.executable, str(script), *sys.argv[1:]]))
