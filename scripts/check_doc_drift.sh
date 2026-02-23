#!/usr/bin/env bash
set -euo pipefail

python3 scripts/check_doc_drift.py

python3 - <<'PY'
from pathlib import Path
import re

roots = [Path('README.md')] + sorted(Path('docs').rglob('*.md'))
link_re = re.compile(r'\[[^\]]+\]\(([^)]+)\)')
failures = []

for md in roots:
    text = md.read_text(encoding='utf-8')
    for i, line in enumerate(text.splitlines(), start=1):
        for target in link_re.findall(line):
            target = target.strip()
            if not target or target.startswith(('http://', 'https://', 'mailto:', '#')):
                continue
            target = target.split('#', 1)[0]
            if target.startswith('<') and target.endswith('>'):
                target = target[1:-1]
            path = (md.parent / target).resolve()
            if not path.exists():
                failures.append(f"{md}:{i} -> {target}")

if failures:
    print('Broken local markdown links found:')
    for f in failures:
        print(f' - {f}')
    raise SystemExit(1)

print(f'Local markdown links OK across {len(roots)} files.')
PY
