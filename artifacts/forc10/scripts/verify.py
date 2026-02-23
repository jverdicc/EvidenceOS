#!/usr/bin/env python3
"""Compatibility wrapper for FORC10 output verification."""

from pathlib import Path
import subprocess
import sys


if __name__ == '__main__':
    script = Path(__file__).resolve().parents[1] / 'original_python' / 'verify_outputs.py'
    translated = []
    args = iter(sys.argv[1:])
    for arg in args:
        if arg == '--golden-dir':
            translated.extend(['--expected-dir', next(args)])
        else:
            translated.append(arg)
    raise SystemExit(subprocess.call([sys.executable, str(script), *translated]))
