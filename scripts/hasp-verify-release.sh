#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./hasp-release-common.sh
source "$script_dir/hasp-release-common.sh"

usage() {
  cat <<'EOF'
Usage: hasp-verify-release.sh <release-tarball>

Verify a packaged HASP release before install.
EOF
}

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 1
fi

tarball="$(release_abs_path "$1")"
if [[ ! -f "$tarball" ]]; then
  echo "release tarball not found: $tarball" >&2
  exit 1
fi
if ! command -v gpg >/dev/null 2>&1; then
  echo "gpg is required for release verification" >&2
  exit 1
fi
if ! command -v gpgv >/dev/null 2>&1; then
  echo "gpgv is required for release verification" >&2
  exit 1
fi

verify_home="$(release_mktemp_dir hvg)"
extract_dir="$(release_mktemp_dir hve)"
stage_dir="$(release_mktemp_dir hvs)"
trap '/bin/rm -rf "$verify_home" "$extract_dir" "$stage_dir"' EXIT
chmod 700 "$verify_home"

tarball="$(release_stage_tarball_with_sidecars "$tarball" "$stage_dir")"
dist_dir="$stage_dir"
artifact_name="$(basename "${tarball%.tar.gz}")"
checksum_file="$dist_dir/SHA256SUMS"
signature_file="$dist_dir/SHA256SUMS.asc"
public_key_file="$dist_dir/hasp-release-public-key.asc"
tarball_sig_path="$dist_dir/$(basename "$tarball").asc"
binary_sig_path="$dist_dir/${artifact_name}_bin.asc"

release_verify_signed_manifest "$checksum_file" "$signature_file" "$public_key_file"
release_verify_detached_signature "$tarball" "$tarball_sig_path" "$public_key_file"

topdir="$(release_detect_topdir "$tarball")"
release_tar -xzf "$tarball" -C "$extract_dir"
artifact_dir="$extract_dir/$topdir"
if [[ ! -d "$artifact_dir" ]]; then
  echo "release tarball did not extract to expected directory: $topdir" >&2
  exit 1
fi
release_validate_extracted_tree "$artifact_dir"

release_require_manifest "$artifact_dir"
manifest="$artifact_dir/RELEASE_MANIFEST"
artifact_name_expected="$(release_metadata_scalar "$manifest" artifact_name_expected)"
release_files=()
while IFS= read -r release_file; do
  release_files+=("$release_file")
done < <(release_manifest_files "$manifest")

if [[ "$topdir" != "$artifact_name" ]]; then
  echo "release archive directory does not match tarball name" >&2
  exit 1
fi
if [[ "$artifact_name_expected" != "$artifact_name" ]]; then
  echo "release manifest artifact name mismatch" >&2
  exit 1
fi

for path in "${release_files[@]}"; do
  if [[ ! -e "$artifact_dir/$path" ]]; then
    echo "release file missing from artifact: $path" >&2
    exit 1
  fi
done
for supply_chain_file in sbom.spdx.json slsa-provenance.json CODE_SIGNING_STATUS.json REPRODUCIBLE_BUILD.json; do
  if [[ ! -s "$artifact_dir/$supply_chain_file" ]]; then
    echo "release supply-chain artifact missing or empty: $supply_chain_file" >&2
    exit 1
  fi
done
release_verify_detached_signature "$artifact_dir/bin/hasp" "$binary_sig_path" "$public_key_file"

while read -r expected_sum relative_path; do
	[[ -n "$expected_sum" ]] || continue
	case "$relative_path" in
	"$artifact_name".tar.gz)
		target="$tarball"
		;;
	"$artifact_name"/*)
		target="$extract_dir/$relative_path"
		;;
	*.tar.gz)
		target="$dist_dir/$relative_path"
		if [[ ! -f "$target" ]]; then
			continue
		fi
		;;
	hasp_*/bin/hasp)
		continue
		;;
	*)
		target="$dist_dir/$relative_path"
		;;
	esac
	if [[ ! -f "$target" ]]; then
		echo "release checksum target missing: $relative_path" >&2
    exit 1
  fi
  actual_sum="$(release_sha256 "$target")"
  if [[ "$actual_sum" != "$expected_sum" ]]; then
    echo "release checksum mismatch for $relative_path" >&2
    exit 1
  fi
done <"$checksum_file"
