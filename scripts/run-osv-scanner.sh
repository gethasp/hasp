#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$repo_root/bin/tools:$PATH"

if ! command -v osv-scanner >/dev/null 2>&1; then
  printf 'osv-scanner is required; run ./scripts/bootstrap_go_tools.sh verify first.\n' >&2
  exit 1
fi

scan_roots=()
if [[ $# -gt 0 ]]; then
  scan_roots=("$@")
else
  web_app_dir="apps/${HASP_OSV_WEB_APP_DIR_NAME:-web}"
  for candidate in apps/server public/apps/server tools/license-signer "$web_app_dir"; do
    if [[ -e "$repo_root/$candidate" ]]; then
      scan_roots+=("$candidate")
    fi
  done
fi

if [[ "${#scan_roots[@]}" -eq 0 ]]; then
  echo "No dependency roots found for OSV scanning." >&2
  exit 0
fi

# Scan only the dependency roots we own so generated trees stay out of scope.
workspace_root="$(git -C "$repo_root" rev-parse --show-toplevel 2>/dev/null || printf '%s' "$repo_root")"
cache_dir="$workspace_root/.cache/osv-scanner"
mkdir -p "$cache_dir/osv-scanner/Go" "$cache_dir/osv-scanner/npm"
if [[ ! -f "$cache_dir/osv-scanner/Go/all.zip" ]]; then
  curl -4 -fsSL --retry 3 --retry-all-errors --connect-timeout 15 \
    https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip \
    -o "$cache_dir/osv-scanner/Go/all.zip"
fi
if [[ ! -f "$cache_dir/osv-scanner/npm/all.zip" ]]; then
  curl -4 -fsSL --retry 3 --retry-all-errors --connect-timeout 15 \
    https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip \
    -o "$cache_dir/osv-scanner/npm/all.zip"
fi
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$cache_dir"
osv-scanner scan source --offline --recursive --verbosity=error "${scan_roots[@]}"
