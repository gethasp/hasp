#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./hasp-release-common.sh
source "$script_dir/hasp-release-common.sh"

usage() {
  cat <<'EOF'
Usage: hasp-upgrade-release.sh [install-flags...] <release-tarball> <install-dir>

Upgrade an existing HASP release tree in place. The script reuses the staged
install path from hasp-install-release.sh and leaves HASP_HOME untouched.
EOF
}

if [[ $# -lt 2 ]]; then
  usage >&2
  exit 1
fi

args=("$@")
install_dir="${args[${#args[@]}-1]}"
if [[ ! -d "$install_dir" ]]; then
  printf 'install directory not found: %s\n' "$install_dir" >&2
  exit 1
fi

receipt_path="$install_dir/INSTALL_RECEIPT"
previous_version="unknown"
if [[ -f "$receipt_path" ]]; then
  previous_version="$(release_metadata_scalar "$receipt_path" installed_version 2>/dev/null || printf 'unknown')"
fi

bash "$script_dir/hasp-install-release.sh" "${args[@]}"

if [[ -f "$install_dir/INSTALL_RECEIPT" ]]; then
  {
    printf 'previous_version=%q\n' "$previous_version"
    printf 'upgraded_at=%q\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >>"$install_dir/INSTALL_RECEIPT"
fi
