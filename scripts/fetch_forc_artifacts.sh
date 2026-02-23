#!/usr/bin/env bash
set -euo pipefail

DOI="${FORC_ZENODO_DOI:-10.5281/zenodo.18685556}"
RECORD_ID="${FORC_ZENODO_RECORD_ID:-18685556}"
API_URL="${FORC_ZENODO_API_URL:-https://zenodo.org/api/records/${RECORD_ID}}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_EXPERIMENTS_DIR="${ROOT_DIR}/experiments"

mkdir -p "${TARGET_EXPERIMENTS_DIR}"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

META_JSON="${TMP_DIR}/record.json"
ARCHIVE_FILE=""

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

download_file() {
  local url="$1"
  local output="$2"

  if have_cmd curl; then
    curl -fL --retry 3 --connect-timeout 20 --max-time 600 -o "${output}" "${url}"
  elif have_cmd wget; then
    wget -O "${output}" "${url}"
  else
    echo "error: neither curl nor wget is available" >&2
    exit 1
  fi
}

echo "[forc-artifacts] Resolving DOI ${DOI} via Zenodo record ${RECORD_ID}"
download_file "${API_URL}" "${META_JSON}"

DOWNLOAD_URL="$(python3 - "${META_JSON}" <<'PY'
import json
import sys
from pathlib import Path

meta = json.loads(Path(sys.argv[1]).read_text())
files = meta.get("files", [])
if not files:
    raise SystemExit("error: Zenodo record has no files")

preferred = None
for f in files:
    key = f.get("key", "")
    if key.endswith((".zip", ".tar.gz", ".tgz")) and ("forc" in key.lower() or "artifact" in key.lower()):
        preferred = f
        break

if preferred is None:
    for f in files:
        key = f.get("key", "")
        if key.endswith((".zip", ".tar.gz", ".tgz")):
            preferred = f
            break

if preferred is None:
    preferred = files[0]

links = preferred.get("links", {})
url = links.get("self") or links.get("download")
if not url:
    raise SystemExit("error: unable to find a download URL in Zenodo metadata")

print(url)
PY
)"

ARCHIVE_FILE="${TMP_DIR}/archive"
echo "[forc-artifacts] Downloading artifact archive"
download_file "${DOWNLOAD_URL}" "${ARCHIVE_FILE}"

EXTRACT_DIR="${TMP_DIR}/extract"
mkdir -p "${EXTRACT_DIR}"

echo "[forc-artifacts] Extracting archive"
if have_cmd bsdtar; then
  bsdtar -xf "${ARCHIVE_FILE}" -C "${EXTRACT_DIR}" || true
fi

if [ -z "$(find "${EXTRACT_DIR}" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  if have_cmd unzip; then
    unzip -q "${ARCHIVE_FILE}" -d "${EXTRACT_DIR}" || true
  fi
fi

if [ -z "$(find "${EXTRACT_DIR}" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  if have_cmd tar; then
    tar -xf "${ARCHIVE_FILE}" -C "${EXTRACT_DIR}"
  else
    echo "error: could not extract archive (need bsdtar/unzip/tar)" >&2
    exit 1
  fi
fi

echo "[forc-artifacts] Restoring paper path directory: experiments/"
FOUND_EXPERIMENTS=0
while IFS= read -r src_dir; do
  FOUND_EXPERIMENTS=1
  rsync -a "${src_dir}/" "${TARGET_EXPERIMENTS_DIR}/"
done < <(find "${EXTRACT_DIR}" -type d -name experiments)

if [ "${FOUND_EXPERIMENTS}" -eq 0 ]; then
  echo "error: no experiments/ directory found in downloaded artifact archive" >&2
  exit 1
fi

echo "[forc-artifacts] Completed. Restored files under ${TARGET_EXPERIMENTS_DIR}"
