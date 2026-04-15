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
  HASP_RELEASE_BASE_URL   base URL used for generated release metadata
  HASP_RELEASE_GPG_KEY_ID optional explicit signing key id
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
base_url="${HASP_RELEASE_BASE_URL:-https://downloads.gethasp.com/hasp/releases}/v${release_tag}"

/bin/rm -rf "$release_root"
/bin/mkdir -p "$release_root"

targets=(
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
)

for target in "${targets[@]}"; do
  read -r goos goarch <<<"$target"
  (
    export GOOS="$goos"
    export GOARCH="$goarch"
    bash "$repo_root/scripts/package-release.sh" >/dev/null
    /bin/cp -f "$repo_root"/dist/release/*.tar.gz "$release_root"/
    /bin/rm -rf "$repo_root/dist/release"
  )
done

bash "$repo_root/scripts/assemble-public-release.sh" "$release_root" "$base_url"

echo "$release_root"
