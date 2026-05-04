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
  HASP_RELEASE_GPG_PASSPHRASE             optional passphrase for loopback signing
  HASP_RELEASE_GPG_PASSPHRASE_FILE        optional file containing the passphrase
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
fingerprint_path="$dist_dir/RELEASE-SIGNING-FINGERPRINT.txt"

signing_key="${HASP_RELEASE_GPG_KEY_ID:-}"

if [[ -z "$signing_key" ]]; then
  signing_key_file="$(mktemp)"
  release_select_signing_key >"$signing_key_file"
  signing_key="$(<"$signing_key_file")"
  /bin/rm -f "$signing_key_file"
fi
if [[ -z "$signing_key" ]]; then
  echo "failed to resolve a release signing key" >&2
  exit 1
fi
signing_fingerprint="$(release_signing_fingerprint "$signing_key")"
if [[ -z "$signing_fingerprint" ]]; then
  echo "failed to resolve release signing fingerprint" >&2
  exit 1
fi
release_require_allowed_signing_fingerprint "$signing_fingerprint" "release signing key"
release_export_public_key "$signing_key" "$public_key_file"
printf '%s\n' "$signing_fingerprint" >"$fingerprint_path"

{
  printf '%s  %s\n' "$(release_sha256 "$tarball")" "$(basename "$tarball")"
  printf '%s  %s\n' "$(release_sha256 "$artifact_dir/bin/hasp")" "$artifact_name/bin/hasp"
} >"$checksum_file"
release_detached_sign "$signing_key" "$checksum_file" "$signature_file"
release_detached_sign "$signing_key" "$tarball" "$tarball_sig_path"
release_detached_sign "$signing_key" "$artifact_dir/bin/hasp" "$binary_sig_path"

if [[ ! -s "$checksum_file" || ! -s "$signature_file" || ! -s "$public_key_file" || ! -s "$fingerprint_path" || ! -s "$tarball_sig_path" || ! -s "$binary_sig_path" ]]; then
  echo "signing output incomplete" >&2
  exit 1
fi
