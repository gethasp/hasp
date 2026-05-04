#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./hasp-release-common.sh
source "$script_dir/hasp-release-common.sh"

usage() {
  cat <<'EOF'
Usage: package-public-release.sh <release-tag> [output-dir]

Build the packaged public release set under dist/public-release/<release-tag>.

Environment:
  HASP_RELEASE_BASE_URL         base URL used for generated release metadata
  HASP_RELEASE_GPG_KEY_ID       optional explicit signing key id
  HASP_UPGRADE_TRUST_ROOTS_HEX  comma-separated Ed25519 public roots embedded in release binaries
  HASP_UPGRADE_SIGNING_KEY_FILE path to raw Ed25519 private key for hasp upgrade artifacts
  HASP_UPGRADE_SIGNING_KEY_B64  base64 raw Ed25519 private key for hasp upgrade artifacts
EOF
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage >&2
  exit 1
fi

release_tag="$1"
release_tag="${release_tag#refs/tags/}"
release_tag="${release_tag#v}"

repo_root="$(git -C "$script_dir/.." rev-parse --show-toplevel 2>/dev/null || pwd)"
release_root="${2:-$repo_root/dist/public-release/v${release_tag}}"
release_root="$(release_abs_path "$release_root")"
base_url_root="${HASP_RELEASE_BASE_URL:-https://downloads.gethasp.com/hasp/releases}"
release_require_publication_base "$base_url_root"
base_url="${base_url_root%/}/v${release_tag}"
package_public_tmp="$(release_mktemp_dir hpp)"

package_public_cleanup() {
  if [[ -n "$package_public_tmp" && -d "$package_public_tmp" ]]; then
    /bin/rm -rf "$package_public_tmp" || true
  fi
  release_cleanup
}
trap package_public_cleanup EXIT

/bin/rm -rf "$release_root"
/bin/mkdir -p "$release_root"

while read -r goos goarch _runner; do
  (
    export GOOS="$goos"
    export GOARCH="$goarch"
    target_release_root="$package_public_tmp/${goos}-${goarch}"
    /bin/rm -rf "$target_release_root"
    /bin/mkdir -p "$target_release_root"
    export HASP_RELEASE_ROOT="$target_release_root"
    bash "$repo_root/scripts/package-release.sh" >/dev/null
    /bin/cp -f "$target_release_root"/*.tar.gz "$release_root"/
  )
done < <(python3 "$repo_root/scripts/release_targets.py" shell)

bash "$repo_root/scripts/assemble-public-release.sh" "$release_root" "$base_url"

echo "$release_root"
