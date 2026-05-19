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
export HASP_BUILD_DATE="${HASP_BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

package_public_cleanup() {
  if [[ -n "$package_public_tmp" && -d "$package_public_tmp" ]]; then
    /bin/rm -rf "$package_public_tmp" || true
  fi
  release_cleanup
}
trap package_public_cleanup EXIT

detect_package_jobs() {
  local target_count="$1"
  local jobs="${HASP_PACKAGE_PUBLIC_RELEASE_JOBS:-}"
  local cpu_count=""

  if [[ -z "$jobs" ]]; then
    cpu_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || printf '1')"
    [[ "$cpu_count" =~ ^[0-9]+$ && "$cpu_count" -gt 0 ]] || cpu_count=1
    jobs="$cpu_count"
    if [[ "$jobs" -gt "$target_count" ]]; then
      jobs="$target_count"
    fi
  fi

  if [[ ! "$jobs" =~ ^[0-9]+$ || "$jobs" -lt 1 ]]; then
    printf 'HASP_PACKAGE_PUBLIC_RELEASE_JOBS must be a positive integer\n' >&2
    return 2
  fi

  printf '%s\n' "$jobs"
}

package_one_target() {
  local goos="$1"
  local goarch="$2"
  local target_release_root="$package_public_tmp/${goos}-${goarch}"

  export GOOS="$goos"
  export GOARCH="$goarch"
  if [[ "$goos" == "darwin" ]]; then
    export CGO_ENABLED=1
  else
    export CGO_ENABLED=0
  fi
  export HASP_RELEASE_ROOT="$target_release_root"
  export HASP_PACKAGE_RELEASE_UNSIGNED=1

  /bin/rm -rf "$target_release_root"
  /bin/mkdir -p "$target_release_root"
  bash "$repo_root/scripts/package-release.sh" >/dev/null
  /bin/cp -f "$target_release_root"/*.tar.gz "$release_root"/
}

/bin/rm -rf "$release_root"
/bin/mkdir -p "$release_root"

targets_file="$package_public_tmp/targets.txt"
python3 "$repo_root/scripts/release_targets.py" shell >"$targets_file"
target_count="$(wc -l <"$targets_file" | tr -d '[:space:]')"
if [[ "$target_count" -lt 1 ]]; then
  printf 'release target list is empty\n' >&2
  exit 1
fi
package_jobs="$(detect_package_jobs "$target_count")"
pids=()
logs=()
failed=0

wait_for_oldest_package() {
  local pid="${pids[0]}"
  local log_path="${logs[0]}"
  if ! wait "$pid"; then
    failed=1
    cat "$log_path" >&2 || true
  fi
  pids=("${pids[@]:1}")
  logs=("${logs[@]:1}")
}

while read -r goos goarch _runner; do
  log_path="$package_public_tmp/package-${goos}-${goarch}.log"
  package_one_target "$goos" "$goarch" >"$log_path" 2>&1 &
  pids+=("$!")
  logs+=("$log_path")
  if [[ "${#pids[@]}" -ge "$package_jobs" ]]; then
    wait_for_oldest_package
  fi
done <"$targets_file"

while [[ "${#pids[@]}" -gt 0 ]]; do
  wait_for_oldest_package
done

if [[ "$failed" != "0" ]]; then
  exit 1
fi

bash "$repo_root/scripts/assemble-public-release.sh" "$release_root" "$base_url"

echo "$release_root"
