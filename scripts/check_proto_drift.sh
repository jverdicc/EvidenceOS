#!/usr/bin/env bash
set -euo pipefail

allowed_prefix="crates/evidenceos-protocol/proto/"
violations=()

while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  if rg -n '^\s*package\s+evidenceos\.' "$file" >/dev/null; then
    if [[ "$file" != ${allowed_prefix}* ]]; then
      violations+=("$file")
    fi
  fi
done < <(find . -type f -name '*.proto' -print | sed 's#^./##')

if (( ${#violations[@]} > 0 )); then
  echo "Protocol drift detected: local evidenceos.* proto definitions outside ${allowed_prefix}" >&2
  printf ' - %s\n' "${violations[@]}" >&2
  exit 1
fi

echo "Proto drift check passed"
