#!/usr/bin/env bash
set -euo pipefail

lock_file="scripts/evidenceos_vendor.lock"
compat_file="COMPATIBILITY.md"

if [[ ! -f "$lock_file" ]]; then
  echo "missing $lock_file" >&2
  exit 1
fi

if [[ ! -f "$compat_file" ]]; then
  echo "missing $compat_file" >&2
  exit 1
fi

lock_repo="$(awk -F= '/^repo=/{print $2}' "$lock_file")"
lock_ref="$(awk -F= '/^ref=/{print $2}' "$lock_file")"

if [[ -z "$lock_repo" || -z "$lock_ref" ]]; then
  echo "invalid $lock_file: expected repo= and ref=" >&2
  exit 1
fi

compat_repo="$(sed -n 's/^- Canonical upstream repository: `\(.*\)`/\1/p' "$compat_file")"
compat_ref="$(sed -n 's/^- FORC submission pin: `\(.*\)`/\1/p' "$compat_file")"

if [[ "$lock_repo" != "$compat_repo" ]]; then
  echo "vendor drift: lock repo '$lock_repo' != compatibility repo '$compat_repo'" >&2
  exit 1
fi

if [[ "$lock_ref" != "$compat_ref" ]]; then
  echo "vendor drift: lock ref '$lock_ref' != compatibility ref '$compat_ref'" >&2
  exit 1
fi

echo "vendor lock aligned: $lock_repo @ $lock_ref"
