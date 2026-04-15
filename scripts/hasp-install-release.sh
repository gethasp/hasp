#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./hasp-release-common.sh
source "$script_dir/hasp-release-common.sh"

usage() {
  cat <<'EOF'
Usage: hasp-install-release.sh [--verify|--no-verify] <release-tarball> [install-dir]

Install a packaged HASP release tarball into a local prefix.
EOF
}

verify_release=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify)
      verify_release=1
      shift
      ;;
    --no-verify)
      verify_release=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      printf 'unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage >&2
  exit 1
fi

tarball="$(release_abs_path "$1")"
install_dir="${2:-$HOME/.local/share/hasp/$(basename "${tarball%.tar.gz}")}"
install_dir="$(release_abs_path "$install_dir")"

if [[ ! -f "$tarball" ]]; then
  printf 'release tarball not found: %s\n' "$tarball" >&2
  exit 1
fi

if [[ "$verify_release" -eq 1 ]]; then
  bash "$script_dir/hasp-verify-release.sh" "$tarball"
fi

topdir="$(release_detect_topdir "$tarball")"
tmp_dir="$(mktemp -d)"
stage_dir="${install_dir}.staging.$$"
backup_dir="${install_dir}.backup.$$"

cleanup() {
  /bin/rm -rf "$tmp_dir" "$stage_dir"
}
trap cleanup EXIT

/usr/bin/tar -xzf "$tarball" -C "$tmp_dir"
artifact_dir="$tmp_dir/$topdir"
if [[ ! -d "$artifact_dir" ]]; then
  printf 'release tarball did not contain the expected top-level directory: %s\n' "$topdir" >&2
  exit 1
fi
release_require_manifest "$artifact_dir"

/bin/mkdir -p "$(dirname "$install_dir")"
/bin/rm -rf "$stage_dir"
/bin/cp -R "$artifact_dir" "$stage_dir"
# shellcheck disable=SC1090
source "$stage_dir/RELEASE_MANIFEST"
cat >"$stage_dir/INSTALL_RECEIPT" <<EOF
installed_version='${version}'
artifact_name='${artifact_name_expected}'
source_tarball='${tarball}'
installed_at='$(date -u +%Y-%m-%dT%H:%M:%SZ)'
EOF

if [[ -e "$install_dir" ]]; then
  if [[ -d "$install_dir" ]] && [[ -z "$(/bin/ls -A "$install_dir")" ]]; then
    /bin/rm -rf "$install_dir"
  else
    release_require_manifest "$install_dir"
    /bin/rm -rf "$backup_dir"
    /bin/mv "$install_dir" "$backup_dir"
  fi
fi

if ! /bin/mv "$stage_dir" "$install_dir"; then
  if [[ -d "$backup_dir" ]]; then
    /bin/mv "$backup_dir" "$install_dir"
  fi
  printf 'failed to install release into %s\n' "$install_dir" >&2
  exit 1
fi

if [[ -d "$backup_dir" ]]; then
  /bin/rm -rf "$backup_dir"
fi

"$install_dir/bin/hasp" version >/dev/null
printf '%s\n' "$install_dir"
