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
metadata_signature_file="${metadata_file}.asc"
formula_dir="$release_dir/Formula"
formula_path="$formula_dir/hasp.rb"
cask_dir="$release_dir/Casks"
cask_path="$cask_dir/hasp.rb"
tmp_extract="$(mktemp -d)"
upgrade_signing_key_temp=""
cleanup() {
  /bin/rm -rf "$tmp_extract"
  if [[ -n "$upgrade_signing_key_temp" && -f "$upgrade_signing_key_temp" ]]; then
    /bin/rm -f "$upgrade_signing_key_temp"
  fi
}
trap cleanup EXIT
release_sign_bin="$tmp_extract/release-sign"

(
  cd "$repo_root/apps/server"
  go build -trimpath -buildvcs=false -o "$release_sign_bin" ./cmd/release-sign
)

release_sign_tool() {
  "$release_sign_bin" "$@"
}

resolve_upgrade_signing_key() {
  if [[ -n "${HASP_UPGRADE_SIGNING_KEY_FILE:-}" ]]; then
    if [[ ! -f "$HASP_UPGRADE_SIGNING_KEY_FILE" ]]; then
      printf 'upgrade signing key file not found: %s\n' "$HASP_UPGRADE_SIGNING_KEY_FILE" >&2
      return 1
    fi
    printf '%s\n' "$HASP_UPGRADE_SIGNING_KEY_FILE"
    return 0
  fi
  if [[ -n "${HASP_UPGRADE_SIGNING_KEY_B64:-}" ]]; then
    upgrade_signing_key_temp="$(mktemp)"
    chmod 600 "$upgrade_signing_key_temp"
    if ! printf '%s' "$HASP_UPGRADE_SIGNING_KEY_B64" | release_base64_decode >"$upgrade_signing_key_temp"; then
      printf 'failed to decode HASP_UPGRADE_SIGNING_KEY_B64\n' >&2
      return 1
    fi
    printf '%s\n' "$upgrade_signing_key_temp"
    return 0
  fi
  printf 'missing upgrade signing key; set HASP_UPGRADE_SIGNING_KEY_FILE or HASP_UPGRADE_SIGNING_KEY_B64\n' >&2
  return 1
}

write_upgrade_keys() {
  local keys_path="$1"
  if [[ -z "${HASP_UPGRADE_TRUST_ROOTS_HEX:-}" ]]; then
    printf 'missing HASP_UPGRADE_TRUST_ROOTS_HEX; cannot generate upgrade KEYS file\n' >&2
    return 1
  fi

  : >"$keys_path"
  local roots_csv="$HASP_UPGRADE_TRUST_ROOTS_HEX,"
  local root=""
  while [[ -n "$roots_csv" ]]; do
    root="${roots_csv%%,*}"
    roots_csv="${roots_csv#*,}"
    if [[ -z "$root" ]]; then
      continue
    fi
    if [[ ! "$root" =~ ^[0-9a-fA-F]{64}$ ]]; then
      printf 'invalid HASP_UPGRADE_TRUST_ROOTS_HEX entry: %s\n' "$root" >&2
      return 1
    fi
    printf '%s hasp upgrade release signing key\n' "$root" >>"$keys_path"
  done

  if [[ ! -s "$keys_path" ]]; then
    printf 'no upgrade trust roots written to %s\n' "$keys_path" >&2
    return 1
  fi
}

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

/bin/mkdir -p "$formula_dir" "$cask_dir"
release_export_public_key "$signing_key" "$public_key_file"
signing_fingerprint="$(release_signing_fingerprint "$signing_key")"
release_require_allowed_signing_fingerprint "$signing_fingerprint" "release signing key"
printf '%s\n' "$signing_fingerprint" >"$fingerprint_file"
: >"$checksum_file"

release_version="$(cat "$repo_root/VERSION")"
read -r release_sequence release_issued_at release_expires_at < <(
  HASP_RELEASE_METADATA_TTL_DAYS="${HASP_RELEASE_METADATA_TTL_DAYS:-397}" python3 "$script_dir/release_metadata_window.py" "$release_version"
)
upgrade_signing_key="$(resolve_upgrade_signing_key)"
upgrade_pubkey="$(release_sign_tool pubkey --key "$upgrade_signing_key")"
upgrade_keys_file="$release_dir/KEYS-v${release_version}"
upgrade_keys_sig_file="${upgrade_keys_file}.sig"
write_upgrade_keys "$upgrade_keys_file"
if ! awk -v key="$upgrade_pubkey" 'tolower($1) == tolower(key) { found = 1 } END { exit found ? 0 : 1 }' "$upgrade_keys_file"; then
  printf 'upgrade signing key public key %s is not listed in HASP_UPGRADE_TRUST_ROOTS_HEX\n' "$upgrade_pubkey" >&2
  exit 1
fi
release_sign_tool keys --key "$upgrade_signing_key" --in "$upgrade_keys_file" --out "$upgrade_keys_sig_file" >/dev/null
{
  printf '%s  %s\n' "$(release_sha256 "$upgrade_keys_file")" "$(basename "$upgrade_keys_file")"
  printf '%s  %s\n' "$(release_sha256 "$upgrade_keys_sig_file")" "$(basename "$upgrade_keys_sig_file")"
} >>"$checksum_file"

metadata_entries=()
for tarball in "${tarballs[@]}"; do
  tarball_name="$(basename "$tarball")"
  artifact_name="${tarball_name%.tar.gz}"
  IFS='_' read -r product version os arch <<<"$artifact_name"
  if [[ "$product" != "hasp" || -z "$version" || -z "$os" || -z "$arch" ]]; then
    echo "unexpected artifact name: $artifact_name" >&2
    exit 1
  fi
  tarball_sig_path="$release_dir/${tarball_name}.asc"
  binary_sig_path="$release_dir/${artifact_name}_bin.asc"
  upgrade_tarball_name="hasp-v${version}-${os}-${arch}.tar.gz"
  upgrade_tarball_path="$release_dir/$upgrade_tarball_name"
  upgrade_tarball_sig_path="${upgrade_tarball_path}.sig"

  topdir="$(release_detect_topdir "$tarball")"
  work_dir="$tmp_extract/$artifact_name"
  /bin/mkdir -p "$work_dir"
  release_tar -xzf "$tarball" -C "$work_dir"
  artifact_dir="$work_dir/$topdir"
  release_validate_extracted_tree "$artifact_dir"

  if [[ ! -f "$artifact_dir/bin/hasp" ]]; then
    echo "packaged release is missing bin/hasp: $tarball_name" >&2
    exit 1
  fi

  release_detached_sign "$signing_key" "$tarball" "$tarball_sig_path"
  release_detached_sign "$signing_key" "$artifact_dir/bin/hasp" "$binary_sig_path"
  /bin/cp -f "$tarball" "$upgrade_tarball_path"
  release_sign_tool tarball --key "$upgrade_signing_key" --in "$upgrade_tarball_path" --out "$upgrade_tarball_sig_path" >/dev/null
  release_sign_tool verify \
    --roots-hex "$HASP_UPGRADE_TRUST_ROOTS_HEX" \
    --keys "$upgrade_keys_file" \
    --keys-sig "$upgrade_keys_sig_file" \
    --tarball "$upgrade_tarball_path" \
    --tarball-sig "$upgrade_tarball_sig_path" >/dev/null

  {
    printf '%s  %s\n' "$(release_sha256 "$tarball")" "$tarball_name"
    printf '%s  %s\n' "$(release_sha256 "$artifact_dir/bin/hasp")" "${artifact_name}/bin/hasp"
    printf '%s  %s\n' "$(release_sha256 "$upgrade_tarball_path")" "$upgrade_tarball_name"
    printf '%s  %s\n' "$(release_sha256 "$upgrade_tarball_sig_path")" "$(basename "$upgrade_tarball_sig_path")"
  } >>"$checksum_file"

  metadata_entries+=("    {\"name\":\"$artifact_name\",\"version\":\"$version\",\"os\":\"$os\",\"arch\":\"$arch\",\"tarball\":\"$tarball_name\",\"url\":\"$base_url/$tarball_name\",\"sha256\":\"$(release_sha256 "$tarball")\"}")
done

{
  printf '{\n'
  printf '  "tag_base_url": "%s",\n' "$base_url"
  printf '  "version": "%s",\n' "$release_version"
  printf '  "release_sequence": %s,\n' "$release_sequence"
  printf '  "issued_at": "%s",\n' "$release_issued_at"
  printf '  "expires_at": "%s",\n' "$release_expires_at"
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

release_detached_sign "$signing_key" "$metadata_file" "$metadata_signature_file"
{
  printf '%s  %s\n' "$(release_sha256 "$metadata_file")" "$(basename "$metadata_file")"
  printf '%s  %s\n' "$(release_sha256 "$metadata_signature_file")" "$(basename "$metadata_signature_file")"
} >>"$checksum_file"
release_detached_sign "$signing_key" "$checksum_file" "$signature_file"

bash "$script_dir/render-homebrew-formula.sh" --metadata "$metadata_file" "$formula_path" >/dev/null
if [[ -n "${HASP_MACOS_DMG_SHA256:-}" ]]; then
  bash "$script_dir/render-homebrew-cask.sh" \
    "${HASP_MACOS_DMG_URL:-https://download.gethasp.com/macos/HASP-${release_version}.dmg}" \
    "$HASP_MACOS_DMG_SHA256" \
    "$cask_path" >/dev/null
fi

if [[ ! -s "$checksum_file" || ! -s "$signature_file" || ! -s "$public_key_file" || ! -s "$metadata_file" || ! -s "$metadata_signature_file" || ! -s "$formula_path" || ! -s "$upgrade_keys_file" || ! -s "$upgrade_keys_sig_file" ]]; then
  echo "public release assembly output incomplete" >&2
  exit 1
fi
