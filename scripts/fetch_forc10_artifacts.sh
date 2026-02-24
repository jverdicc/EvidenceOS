#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${ROOT_DIR}/artifacts/forc10/FULL_ARTIFACT_MANIFEST.json"
SOURCE="remote"
OUT_DIR="${ROOT_DIR}/artifacts/forc10"
LOCAL_ARCHIVE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="$2"
      shift 2
      ;;
    --source)
      SOURCE="$2"
      shift 2
      ;;
    --local-archive)
      LOCAL_ARCHIVE="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

read_manifest_field() {
  local key="$1"
  python3 - "$MANIFEST" "$key" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
value = manifest
for part in sys.argv[2].split('.'):
    value = value[part]
print(value)
PY
}

manifest_check_required_files() {
  python3 - "$MANIFEST" "$ROOT_DIR" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
root = Path(sys.argv[2])
for item in manifest["required_files"]:
    path = root / item["path"]
    if not path.exists():
        raise SystemExit(f"error: required file missing: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != item["sha256"]:
        raise SystemExit(f"error: checksum mismatch for {path} (expected {item['sha256']}, got {digest})")
print("[forc10-fetch] required file checksums verified")
PY
}

verify_sha256() {
  local file_path="$1"
  local expected_sha="$2"
  local actual_sha
  actual_sha="$(sha256sum "$file_path" | awk '{print $1}')"
  if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "error: checksum mismatch for ${file_path}" >&2
    echo "expected: ${expected_sha}" >&2
    echo "actual:   ${actual_sha}" >&2
    exit 1
  fi
}

download_file() {
  local url="$1"
  local output="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --connect-timeout 20 --max-time 600 -o "${output}" "${url}"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "${output}" "${url}"
  else
    echo "error: neither curl nor wget is available" >&2
    exit 1
  fi
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
ARCHIVE_PATH="${TMP_DIR}/forc10.tar.gz"
EXPECTED_SHA="$(read_manifest_field 'sources.remote.sha256')"

if [[ "$SOURCE" == "remote" ]]; then
  URL="$(read_manifest_field 'sources.remote.archive_url')"
  echo "[forc10-fetch] source=remote url=${URL}"
  download_file "${URL}" "${ARCHIVE_PATH}"
elif [[ "$SOURCE" == "local" ]]; then
  if [[ -z "$LOCAL_ARCHIVE" ]]; then
    echo "error: --source local requires --local-archive <path>" >&2
    exit 1
  fi
  cp "$LOCAL_ARCHIVE" "${ARCHIVE_PATH}"
  echo "[forc10-fetch] source=local path=${LOCAL_ARCHIVE}"
else
  echo "error: unsupported source '${SOURCE}' (allowed: remote, local)" >&2
  exit 1
fi

verify_sha256 "${ARCHIVE_PATH}" "${EXPECTED_SHA}"
echo "[forc10-fetch] archive checksum verified"

mkdir -p "${OUT_DIR}"
tar -xzf "${ARCHIVE_PATH}" -C "${OUT_DIR}"
manifest_check_required_files

echo "[forc10-fetch] ready: FULL artifact bundle prepared in ${OUT_DIR}"
