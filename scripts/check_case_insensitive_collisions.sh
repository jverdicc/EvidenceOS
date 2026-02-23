#!/usr/bin/env bash
set -euo pipefail

lowered_paths=$(mktemp)
trap 'rm -f "$lowered_paths"' EXIT

git ls-files | tr '[:upper:]' '[:lower:]' | sort > "$lowered_paths"

duplicates=$(uniq -d "$lowered_paths" || true)

if [[ -n "$duplicates" ]]; then
  echo "Case-insensitive path collisions detected among tracked files:" >&2
  while IFS= read -r lowered; do
    [[ -z "$lowered" ]] && continue
    echo "- $lowered" >&2
    git ls-files | awk -v target="$lowered" 'tolower($0)==target {print "    " $0}' >&2
  done <<< "$duplicates"
  exit 1
fi

echo "No case-insensitive path collisions found."
