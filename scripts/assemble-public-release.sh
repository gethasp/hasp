#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./hasp-release-common.sh
source "$script_dir/hasp-release-common.sh"

usage() {
  cat <<'EOF'
Usage: assemble-public-release.sh <release-dir> <base-url>

Generate shared verification material and metadata for a directory of
packaged HASP tarballs.
EOF
}

if [[ $# -ne 2 ]]; then
  usage >&2
  exit 1
fi

release_dir="$(release_abs_path "$1")"
base_url="${2%/}"
repo_root="$(git -C "$script_dir/.." rev-parse --show-toplevel 2>/dev/null || pwd)"

if [[ ! -d "$release_dir" ]]; then
  echo "release directory not found: $release_dir" >&2
  exit 1
fi
if ! command -v gpg >/dev/null 2>&1; then
  echo "gpg is required for public release assembly" >&2
  exit 1
fi

tarballs=()
while IFS= read -r tarball; do
  tarballs+=("$tarball")
done < <(find "$release_dir" -maxdepth 1 -type f -name 'hasp_*.tar.gz' | sort)
if [[ "${#tarballs[@]}" -eq 0 ]]; then
  echo "no release tarballs found in $release_dir" >&2
  exit 1
fi

checksum_file="$release_dir/SHA256SUMS"
signature_file="$release_dir/SHA256SUMS.asc"
public_key_file="$release_dir/hasp-release-public-key.asc"
fingerprint_file="$release_dir/RELEASE-SIGNING-FINGERPRINT.txt"
metadata_file="$release_dir/release-metadata.json"
formula_dir="$release_dir/Formula"
formula_path="$formula_dir/hasp.rb"
tmp_extract="$(mktemp -d)"
cleanup() {
  /bin/rm -rf "$tmp_extract"
}
trap cleanup EXIT

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

/bin/mkdir -p "$formula_dir"
release_export_public_key "$signing_key" "$public_key_file"
signing_fingerprint="$(release_gpg --list-keys --with-colons "$signing_key" | awk -F: '/^fpr:/ {print $10; exit}')"
printf '%s\n' "$signing_fingerprint" >"$fingerprint_file"
: >"$checksum_file"

metadata_entries=()
for tarball in "${tarballs[@]}"; do
  tarball_name="$(basename "$tarball")"
  artifact_name="${tarball_name%.tar.gz}"
  tarball_sig_path="$release_dir/${tarball_name}.asc"
  binary_sig_path="$release_dir/${artifact_name}_bin.asc"

  topdir="$(release_detect_topdir "$tarball")"
  work_dir="$tmp_extract/$artifact_name"
  /bin/mkdir -p "$work_dir"
  /usr/bin/tar -xzf "$tarball" -C "$work_dir"
  artifact_dir="$work_dir/$topdir"

  if [[ ! -f "$artifact_dir/bin/hasp" ]]; then
    echo "packaged release is missing bin/hasp: $tarball_name" >&2
    exit 1
  fi

  release_detached_sign "$signing_key" "$tarball" "$tarball_sig_path"
  release_detached_sign "$signing_key" "$artifact_dir/bin/hasp" "$binary_sig_path"

  printf '%s  %s\n' "$(release_sha256 "$tarball")" "$tarball_name" >>"$checksum_file"
  printf '%s  %s\n' "$(release_sha256 "$artifact_dir/bin/hasp")" "${artifact_name}/bin/hasp" >>"$checksum_file"

  IFS='_' read -r product version os arch <<<"$artifact_name"
  if [[ "$product" != "hasp" || -z "$version" || -z "$os" || -z "$arch" ]]; then
    echo "unexpected artifact name: $artifact_name" >&2
    exit 1
  fi
  metadata_entries+=("    {\"name\":\"$artifact_name\",\"version\":\"$version\",\"os\":\"$os\",\"arch\":\"$arch\",\"tarball\":\"$tarball_name\",\"url\":\"$base_url/$tarball_name\",\"sha256\":\"$(release_sha256 "$tarball")\"}")
done

release_detached_sign "$signing_key" "$checksum_file" "$signature_file"

{
  printf '{\n'
  printf '  "tag_base_url": "%s",\n' "$base_url"
  printf '  "version": "%s",\n' "$(cat "$repo_root/VERSION")"
  printf '  "artifacts": [\n'
  for i in "${!metadata_entries[@]}"; do
    printf '%s' "${metadata_entries[$i]}"
    if [[ "$i" -lt $((${#metadata_entries[@]} - 1)) ]]; then
      printf ','
    fi
    printf '\n'
  done
  printf '  ]\n'
  printf '}\n'
} >"$metadata_file"

bash "$script_dir/render-homebrew-formula.sh" --metadata "$metadata_file" "$formula_path" >/dev/null

if [[ ! -s "$checksum_file" || ! -s "$signature_file" || ! -s "$public_key_file" || ! -s "$metadata_file" || ! -s "$formula_path" ]]; then
  echo "public release assembly output incomplete" >&2
  exit 1
fi
