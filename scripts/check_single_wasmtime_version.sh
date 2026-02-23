#!/usr/bin/env bash
set -euo pipefail

lock_file="${1:-Cargo.lock}"

if [[ ! -f "$lock_file" ]]; then
  echo "error: lockfile not found: $lock_file" >&2
  exit 1
fi

versions=$(awk '
  $0 == "[[package]]" {
    in_pkg = 1
    is_wasmtime = 0
    next
  }
  in_pkg && /^name = / {
    is_wasmtime = ($0 == "name = \"wasmtime\"")
    next
  }
  in_pkg && is_wasmtime && /^version = / {
    split($0, parts, "\"")
    if (length(parts) >= 2) {
      print parts[2]
    }
    in_pkg = 0
    is_wasmtime = 0
  }
' "$lock_file" | sort -u)

count=$(printf '%s\n' "$versions" | sed '/^$/d' | wc -l | tr -d ' ')

if [[ "$count" -ne 1 ]]; then
  echo "error: expected exactly one wasmtime version in $lock_file; found $count" >&2
  if [[ -n "$versions" ]]; then
    echo "versions:" >&2
    while IFS= read -r version; do
      [[ -z "$version" ]] && continue
      echo "  - $version" >&2
    done <<< "$versions"
  fi
  exit 1
fi

echo "Single wasmtime version confirmed: $versions"
