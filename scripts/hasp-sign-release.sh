#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./hasp-release-common.sh
source "$script_dir/hasp-release-common.sh"

usage() {
  cat <<'EOF'
Usage: hasp-sign-release.sh <artifact-dir> <release-tarball>

Generate release verification material for a packaged HASP artifact.

Environment:
  HASP_RELEASE_GPG_KEY_ID                 preferred explicit signing key
  HASP_RELEASE_GPG_HOMEDIR                optional explicit GPG home
  HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING=1  opt-in local dev/smoke fallback
EOF
}

if [[ $# -ne 2 ]]; then
  usage >&2
  exit 1
fi

artifact_dir="$(release_abs_path "$1")"
tarball="$(release_abs_path "$2")"

if [[ ! -d "$artifact_dir" ]]; then
  echo "artifact directory not found: $artifact_dir" >&2
  exit 1
fi
if [[ ! -f "$tarball" ]]; then
  echo "release tarball not found: $tarball" >&2
  exit 1
fi
if ! command -v gpg >/dev/null 2>&1; then
  echo "gpg is required for release signing" >&2
  exit 1
fi

dist_dir="$(cd "$(dirname "$tarball")" && pwd)"
artifact_name="$(basename "$artifact_dir")"
checksum_file="$dist_dir/SHA256SUMS"
signature_file="$dist_dir/SHA256SUMS.asc"
public_key_file="$dist_dir/hasp-release-public-key.asc"
tarball_sig_path="$dist_dir/$(basename "$tarball").asc"
binary_sig_path="$dist_dir/${artifact_name}_bin.asc"

signing_home="${HASP_RELEASE_GPG_HOMEDIR:-}"
signing_key="${HASP_RELEASE_GPG_KEY_ID:-}"
cleanup_home=""

if [[ -z "$signing_key" ]]; then
  signing_key="$(release_select_signing_key)"
fi
if [[ -n "${release_ephemeral_gnupghome:-}" ]]; then
  signing_home="$release_ephemeral_gnupghome"
  cleanup_home="$signing_home"
fi
if [[ -z "$signing_home" ]]; then
  signing_home="${GNUPGHOME:-$HOME/.gnupg}"
fi

trap 'if [[ -n "$cleanup_home" ]]; then rm -rf "$cleanup_home"; fi' EXIT

gpg --batch --homedir "$signing_home" --armor --export "$signing_key" >"$public_key_file"

{
  printf '%s  %s\n' "$(release_sha256 "$tarball")" "$(basename "$tarball")"
  printf '%s  %s\n' "$(release_sha256 "$artifact_dir/bin/hasp")" "$artifact_name/bin/hasp"
} >"$checksum_file"
gpg --homedir "$signing_home" --batch --yes --armor --detach-sign --local-user "$signing_key" \
  --output "$signature_file" "$checksum_file"
GNUPGHOME="$signing_home" release_detached_sign "$signing_key" "$tarball" "$tarball_sig_path"
GNUPGHOME="$signing_home" release_detached_sign "$signing_key" "$artifact_dir/bin/hasp" "$binary_sig_path"

if [[ ! -s "$checksum_file" || ! -s "$signature_file" || ! -s "$public_key_file" || ! -s "$tarball_sig_path" || ! -s "$binary_sig_path" ]]; then
  echo "signing output incomplete" >&2
  exit 1
fi
