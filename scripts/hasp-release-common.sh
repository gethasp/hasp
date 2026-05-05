#!/usr/bin/env bash
set -euo pipefail

release_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_ephemeral_gnupghome=""
release_ephemeral_passphrase_file=""
release_default_trusted_gpg_fingerprints="1519745EA1129CF21EC3988DAF29D6911661DEE3"
release_default_trusted_gpg_fingerprints_file="$release_script_dir/release-trusted-gpg-fingerprints.txt"
# shellcheck source=./release-public-key-trust.sh
source "$release_script_dir/release-public-key-trust.sh"

release_cleanup() {
  if [[ -n "$release_ephemeral_gnupghome" && -d "$release_ephemeral_gnupghome" ]]; then
    /bin/rm -rf "$release_ephemeral_gnupghome" || true
  fi
  if [[ -n "$release_ephemeral_passphrase_file" && -f "$release_ephemeral_passphrase_file" ]]; then
    /bin/rm -f "$release_ephemeral_passphrase_file"
  fi
}

trap release_cleanup EXIT

release_abs_path() {
  local target="$1"
  if [[ "$target" == /* ]]; then
    if [[ -d "$target" ]]; then
      (
        cd "$target"
        pwd -P
      )
      return 0
    fi
    if [[ -d "$(dirname "$target")" ]]; then
      (
        cd "$(dirname "$target")"
        printf '%s/%s\n' "$(pwd -P)" "$(basename "$target")"
      )
      return 0
    fi
    printf '%s\n' "$target"
    return 0
  fi
  if [[ -d "$(dirname "$target")" ]]; then
    (
      cd "$(dirname "$target")"
      printf '%s/%s\n' "$(pwd -P)" "$(basename "$target")"
    )
    return 0
  fi
  printf '%s/%s\n' "$(pwd -P)" "$target"
}

release_sha256() {
  local target="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$target" | awk '{print $1}'
    return 0
  fi
  shasum -a 256 "$target" | awk '{print $1}'
}

release_base64_decode() {
  if base64 --decode </dev/null >/dev/null 2>&1; then
    base64 --decode
    return 0
  fi
  base64 -D
}

release_tar() {
  if ! command -v tar >/dev/null 2>&1; then
    printf 'tar is required for release archive operations\n' >&2
    return 127
  fi
  tar "$@"
}

release_tmp_parent() {
  local parent="${HASP_RELEASE_TMPDIR:-${TMPDIR:-}}"
  if [[ -z "$parent" ]]; then
    return 1
  fi
  /bin/mkdir -p "$parent"
  printf '%s\n' "$parent"
}

release_mktemp_dir() {
  local prefix="${1:-hr}"
  local parent=""
  if parent="$(release_tmp_parent)"; then
    mktemp -d "$parent/$prefix.XXXXXX"
    return 0
  fi
  mktemp -d
}

release_mktemp_file() {
  local prefix="${1:-hr}"
  local parent=""
  if parent="$(release_tmp_parent)"; then
    mktemp "$parent/$prefix.XXXXXX"
    return 0
  fi
  mktemp
}

release_require_publication_base() {
  local base_url="${1%/}"
  if [[ "$base_url" != https://* ]]; then
    printf 'HASP_RELEASE_BASE_URL must be an https URL: %s\n' "$base_url" >&2
    return 1
  fi
}

release_detect_topdir() {
  local tarball="$1"
  local topdir=""
  local line=""
  local entry_type=""
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    entry_type="${line:0:1}"
    case "$entry_type" in
      -|d)
        ;;
      h|l)
        printf 'unsafe archive link entry: %s\n' "$line" >&2
        return 1
        ;;
      *)
        printf 'unsupported archive entry type: %s\n' "$line" >&2
        return 1
        ;;
    esac
  done < <(release_tar -tvzf "$tarball")
  while IFS= read -r line; do
    if [[ "$line" == "" ]]; then
      continue
    fi
    if [[ "$line" == /* || "$line" == *"../"* || "$line" == "../"* ]]; then
      printf 'unsafe archive entry: %s\n' "$line" >&2
      return 1
    fi
    local first_component="${line%%/*}"
    if [[ -z "$topdir" ]]; then
      topdir="$first_component"
    elif [[ "$topdir" != "$first_component" ]]; then
      printf 'archive contains multiple top-level entries: %s and %s\n' "$topdir" "$first_component" >&2
      return 1
    fi
  done < <(release_tar -tzf "$tarball")
  if [[ -z "$topdir" ]]; then
    printf 'release archive is empty: %s\n' "$tarball" >&2
    return 1
  fi
  printf '%s\n' "$topdir"
}

release_private_tarball_copy() {
  local source_tarball="$1"
  local stage_dir="$2"
  local tarball_name
  tarball_name="$(basename "$source_tarball")"
  /bin/mkdir -p "$stage_dir"
  /bin/cp -f "$source_tarball" "$stage_dir/$tarball_name"
  printf '%s\n' "$stage_dir/$tarball_name"
}

release_stage_tarball_with_sidecars() {
  local source_tarball="$1"
  local stage_dir="$2"
  local source_dist
  source_dist="$(cd "$(dirname "$source_tarball")" && pwd)"
  local tarball_name
  tarball_name="$(basename "$source_tarball")"
  local artifact_name="${tarball_name%.tar.gz}"
  local staged_tarball
  staged_tarball="$(release_private_tarball_copy "$source_tarball" "$stage_dir")"

  local required=""
  for required in \
    "SHA256SUMS" \
    "SHA256SUMS.asc" \
    "hasp-release-public-key.asc" \
    "${tarball_name}.asc" \
    "${artifact_name}_bin.asc"
  do
    if [[ ! -f "$source_dist/$required" ]]; then
      printf 'release verification material missing: %s\n' "$source_dist/$required" >&2
      return 1
    fi
    /bin/cp -f "$source_dist/$required" "$stage_dir/$required"
  done

  local checksum_relative=""
  while read -r _ checksum_relative _; do
    [[ -n "$checksum_relative" ]] || continue
    case "$checksum_relative" in
      .|..|/*|./*|../*|*/../*|*/..|*"//"*|*\\*)
        printf 'unsafe checksum sidecar path: %s\n' "$checksum_relative" >&2
        return 1
        ;;
    esac
    case "$checksum_relative" in
      SHA256SUMS|SHA256SUMS.asc|*.tar.gz|"$artifact_name"/*|hasp_*/bin/hasp|*/*)
        continue
        ;;
    esac
    if [[ -f "$source_dist/$checksum_relative" ]]; then
      /bin/cp -f "$source_dist/$checksum_relative" "$stage_dir/$checksum_relative"
    fi
  done <"$source_dist/SHA256SUMS"

  printf '%s\n' "$staged_tarball"
}

release_validate_extracted_tree() {
  local artifact_dir="$1"
  local unsafe=""
  unsafe="$(find "$artifact_dir" ! -type f ! -type d -print -quit)"
  if [[ -n "$unsafe" ]]; then
    printf 'release archive extracted unsupported file type: %s\n' "$unsafe" >&2
    return 1
  fi
  unsafe="$(find "$artifact_dir" -type f -links +1 -print -quit)"
  if [[ -n "$unsafe" ]]; then
    printf 'release archive extracted hardlinked file: %s\n' "$unsafe" >&2
    return 1
  fi
}

release_require_manifest() {
  local install_root="$1"
  if [[ ! -f "$install_root/RELEASE_MANIFEST" ]]; then
    printf 'install root is not a HASP release tree: %s\n' "$install_root" >&2
    return 1
  fi
}

release_validate_metadata_value() {
  local value="$1"
  [[ "$value" =~ ^[A-Za-z0-9._/:+@=-]+$ ]]
}

release_metadata_scalar() {
  local metadata_path="$1"
  local key="$2"
  local line=""
  local value=""

  if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    printf 'invalid metadata key: %s\n' "$key" >&2
    return 1
  fi

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == "$key="* ]] || continue
    value="${line#*=}"
    if [[ "$value" == \'*\' && "${#value}" -ge 2 ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "$value" == \"*\" && "${#value}" -ge 2 ]]; then
      value="${value:1:${#value}-2}"
    fi
    if ! release_validate_metadata_value "$value"; then
      printf 'invalid metadata value for %s in %s\n' "$key" "$metadata_path" >&2
      return 1
    fi
    printf '%s\n' "$value"
    return 0
  done <"$metadata_path"

  printf 'metadata key missing from %s: %s\n' "$metadata_path" "$key" >&2
  return 1
}

release_validate_manifest_path() {
  local value="$1"
  case "$value" in
    ""|.|..|/*|./*|*/./*|*/.|../*|*/../*|*/..|*"//"*)
      return 1
      ;;
  esac
  release_validate_metadata_value "$value"
}

release_sanitize_repo_url() {
  local raw="${HASP_PUBLIC_SOURCE_REPO:-$1}"
  local value
  value="$(
    printf '%s' "$raw" |
      sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*://)[^/@]+@#\1#; s#^[^/@]+@([^:]+:.*)$#\1#'
  )"
  value="${value%%\?*}"
  value="${value%%\#*}"

  if [[ -n "${HASP_PUBLIC_SOURCE_REPO:-}" ]]; then
    printf '%s' "${value:-private-monorepo}"
    return 0
  fi

  case "$value" in
    "https://github.com/gethasp/hasp"|"https://github.com/gethasp/hasp.git"|"ssh://github.com/gethasp/hasp.git"|"github.com:gethasp/hasp.git"|"github.com:gethasp/hasp")
      printf '%s' "https://github.com/gethasp/hasp.git"
      ;;
    "private-monorepo")
      printf '%s' "private-monorepo"
      ;;
    *)
      printf '%s' "private-monorepo"
      ;;
  esac
}

release_source_repo_trailer() {
  printf 'Source-Repo: %s\n' "$(release_sanitize_repo_url "$1")"
}

release_manifest_files() {
  local manifest_path="$1"
  local line=""
  local in_files=0
  local value=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$in_files" -eq 0 ]]; then
      [[ "$line" == "release_files=(" ]] && in_files=1
      continue
    fi

    [[ "$line" == ")" ]] && return 0
    value="$(printf '%s\n' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [[ "$value" == \'*\' && "${#value}" -ge 2 ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "$value" == \"*\" && "${#value}" -ge 2 ]]; then
      value="${value:1:${#value}-2}"
    else
      printf 'invalid release_files entry in %s: %s\n' "$manifest_path" "$line" >&2
      return 1
    fi

    if ! release_validate_manifest_path "$value"; then
      printf 'unsafe release_files entry in %s: %s\n' "$manifest_path" "$value" >&2
      return 1
    fi
    printf '%s\n' "$value"
  done <"$manifest_path"

  printf 'release manifest missing release_files block: %s\n' "$manifest_path" >&2
  return 1
}

release_list_secret_keys() {
  release_gpg --list-secret-keys --with-colons --fingerprint 2>/dev/null | awk -F: '
    $1 == "fpr" { fingerprint = $10 }
    $1 == "uid" && fingerprint != "" { print fingerprint; fingerprint = "" }
  '
}

release_create_ephemeral_key() {
  release_ephemeral_gnupghome="$(release_mktemp_dir hrg)"
  chmod 700 "$release_ephemeral_gnupghome"
  local key_params="$release_ephemeral_gnupghome/key.params"
  local keygen_args=(--batch --pinentry-mode loopback --passphrase '')
  if [[ "${HASP_RELEASE_GPG_DEBUG_QUICK_RANDOM:-}" == "1" ]]; then
    keygen_args+=(--no-tty --debug-quick-random)
  fi
  cat >"$key_params" <<'EOF'
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: HASP Local Release Test Key
Name-Email: hasp@example.invalid
Expire-Date: 1d
%no-protection
%transient-key
%commit
EOF
  GNUPGHOME="$release_ephemeral_gnupghome" gpg "${keygen_args[@]}" --generate-key "$key_params" >/dev/null 2>&1
  export GNUPGHOME="$release_ephemeral_gnupghome"
  release_gpg --list-secret-keys --with-colons --fingerprint 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}'
}

release_gpg() {
  local args=(--batch)
  if [[ -n "${HASP_RELEASE_GPG_HOMEDIR:-}" ]]; then
    args+=(--homedir "$HASP_RELEASE_GPG_HOMEDIR")
  elif [[ -n "$release_ephemeral_gnupghome" ]]; then
    args+=(--homedir "$release_ephemeral_gnupghome")
  elif [[ -n "${GNUPGHOME:-}" ]]; then
    args+=(--homedir "$GNUPGHOME")
  fi
  gpg "${args[@]}" "$@"
}

release_gpgv_verify() {
  local keyring_path="$1"
  local signature_path="$2"
  local input_path="$3"
  local failure_message="$4"
  if ! command -v gpgv >/dev/null 2>&1; then
    printf 'gpgv is required for release verification\n' >&2
    return 1
  fi
  if ! gpgv --keyring "$keyring_path" "$signature_path" "$input_path" >/dev/null 2>&1; then
    printf '%s\n' "$failure_message" >&2
    return 1
  fi
}

release_signing_passphrase_file() {
  if [[ -n "${HASP_RELEASE_GPG_PASSPHRASE_FILE:-}" ]]; then
    if [[ ! -f "$HASP_RELEASE_GPG_PASSPHRASE_FILE" ]]; then
      printf 'release GPG passphrase file not found: %s\n' "$HASP_RELEASE_GPG_PASSPHRASE_FILE" >&2
      return 2
    fi
    printf '%s\n' "$HASP_RELEASE_GPG_PASSPHRASE_FILE"
    return 0
  fi
  if [[ -z "${HASP_RELEASE_GPG_PASSPHRASE:-}" ]]; then
    return 1
  fi
  if [[ -z "$release_ephemeral_passphrase_file" ]]; then
    release_ephemeral_passphrase_file="$(release_mktemp_file hrp)"
    chmod 600 "$release_ephemeral_passphrase_file"
    printf '%s' "$HASP_RELEASE_GPG_PASSPHRASE" >"$release_ephemeral_passphrase_file"
  fi
  printf '%s\n' "$release_ephemeral_passphrase_file"
}

release_select_signing_key() {
  if [[ -n "${HASP_RELEASE_GPG_KEY_ID:-}" ]]; then
    printf '%s\n' "$HASP_RELEASE_GPG_KEY_ID"
    return 0
  fi

  local keys=()
  while IFS= read -r key; do
    if [[ -n "$key" ]]; then
      keys+=("$key")
    fi
  done < <(release_list_secret_keys)

  if [[ "${#keys[@]}" -eq 1 ]]; then
    printf '%s\n' "${keys[0]}"
    return 0
  fi

  if [[ "${#keys[@]}" -eq 0 ]]; then
    if [[ "${HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING:-}" == "1" ]]; then
      release_create_ephemeral_key
      return 0
    fi
    printf 'no GPG signing key found; set HASP_RELEASE_GPG_KEY_ID or HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING=1\n' >&2
    return 1
  fi

  printf 'multiple GPG secret keys found; set HASP_RELEASE_GPG_KEY_ID\n' >&2
  return 1
}

release_export_public_key() {
  local key_id="$1"
  local output_path="$2"
  release_gpg --armor --export "$key_id" >"$output_path"
}

release_normalize_fingerprint() {
  printf '%s' "$1" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]'
}

release_trusted_gpg_fingerprints() {
  if [[ -n "${HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS:-}" ]]; then
    printf '%s\n' "$HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS" | tr ',' '\n'
    return 0
  fi
  if [[ -f "$release_default_trusted_gpg_fingerprints_file" ]]; then
    sed -E 's/#.*$//; s/[[:space:]]+//g; /^$/d' "$release_default_trusted_gpg_fingerprints_file"
    return 0
  fi
  printf '%s\n' "$release_default_trusted_gpg_fingerprints"
}

release_fingerprint_is_trusted() {
  local candidate
  candidate="$(release_normalize_fingerprint "$1")"
  [[ "$candidate" =~ ^[0-9A-F]{40}$ ]] || return 1

  local trusted=""
  local normalized=""
  while IFS= read -r trusted; do
    normalized="$(release_normalize_fingerprint "$trusted")"
    [[ -n "$normalized" ]] || continue
    if [[ ! "$normalized" =~ ^[0-9A-F]{40}$ ]]; then
      printf 'invalid trusted release GPG fingerprint: %s\n' "$trusted" >&2
      return 2
    fi
    if [[ "$candidate" == "$normalized" ]]; then
      return 0
    fi
  done < <(release_trusted_gpg_fingerprints)
  return 1
}

release_fingerprint_is_allowed_for_signing() {
  local candidate
  candidate="$(release_normalize_fingerprint "$1")"
  [[ "$candidate" =~ ^[0-9A-F]{40}$ ]] || return 1
  local status=0
  release_fingerprint_is_trusted "$candidate" || status=$?
  if [[ "$status" -eq 0 ]]; then
    return 0
  fi
  if [[ "$status" -eq 2 ]]; then
    return 2
  fi
  if [[ "${HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING:-}" != "1" || -z "$release_ephemeral_gnupghome" ]]; then
    return 1
  fi
  GNUPGHOME="$release_ephemeral_gnupghome" gpg --batch --list-secret-keys --with-colons "$candidate" 2>/dev/null |
    awk -F: -v candidate="$candidate" '$1 == "fpr" && $10 == candidate { found = 1 } END { exit found ? 0 : 1 }'
}

release_require_trusted_fingerprint() {
  local fingerprint="$1"
  local context="$2"
  local status=0
  release_fingerprint_is_trusted "$fingerprint" || status=$?
  if [[ "$status" -eq 0 ]]; then
    return 0
  fi
  if [[ "$status" -eq 2 ]]; then
    return 2
  fi
  printf 'untrusted %s fingerprint: %s\n' "$context" "$fingerprint" >&2
  printf 'set HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS only for an intentional release-key rotation\n' >&2
  return 1
}

release_require_allowed_signing_fingerprint() {
  local fingerprint="$1"
  local context="$2"
  local status=0
  release_fingerprint_is_allowed_for_signing "$fingerprint" || status=$?
  if [[ "$status" -eq 0 ]]; then
    return 0
  fi
  if [[ "$status" -eq 2 ]]; then
    return 2
  fi
  printf 'untrusted %s fingerprint: %s\n' "$context" "$fingerprint" >&2
  printf 'set HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS for release keys or HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING=1 only for local smoke artifact signing\n' >&2
  return 1
}

release_signing_fingerprint() {
  local key_id="$1"
  release_gpg --list-keys --with-colons "$key_id" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}'
}

release_detached_sign() {
  local key_id="$1"
  local input_path="$2"
  local output_path="$3"
  local args=(--yes --armor --local-user "$key_id" --detach-sign --output "$output_path")
  local passphrase_file=""
  if passphrase_file="$(release_signing_passphrase_file)"; then
    args=(--yes --pinentry-mode loopback --passphrase-file "$passphrase_file" --armor --local-user "$key_id" --detach-sign --output "$output_path")
  else
    local passphrase_status=$?
    if [[ "$passphrase_status" -gt 1 ]]; then
      return 1
    fi
  fi
  if ! release_gpg "${args[@]}" "$input_path"; then
    if [[ -z "${HASP_RELEASE_GPG_PASSPHRASE:-}" && -z "${HASP_RELEASE_GPG_PASSPHRASE_FILE:-}" ]]; then
      printf 'gpg signing failed; if the release key is passphrase-protected in noninteractive environments, set HASP_RELEASE_GPG_PASSPHRASE or HASP_RELEASE_GPG_PASSPHRASE_FILE\n' >&2
    fi
    return 1
  fi
}

release_verify_signed_manifest() {
  local manifest_path="$1"
  local signature_path="$2"
  local public_key_path="$3"
  local verify_home
  local keyring_path
  verify_home="$(release_mktemp_dir hrv)"
  chmod 700 "$verify_home"
  release_import_trusted_public_key "$public_key_path" "$verify_home" || {
    /bin/rm -rf "$verify_home"
    return 1
  }
  keyring_path="$release_trust_keyring_path"
  if ! release_gpgv_verify "$keyring_path" "$signature_path" "$manifest_path" "failed to verify signed checksum manifest: $manifest_path"; then
    /bin/rm -rf "$verify_home"
    return 1
  fi
  /bin/rm -rf "$verify_home"
}

release_verify_detached_signature() {
  local input_path="$1"
  local signature_path="$2"
  local public_key_path="$3"
  local verify_home
  local keyring_path
  verify_home="$(release_mktemp_dir hrv)"
  chmod 700 "$verify_home"
  release_import_trusted_public_key "$public_key_path" "$verify_home" || {
    /bin/rm -rf "$verify_home"
    return 1
  }
  keyring_path="$release_trust_keyring_path"
  if ! release_gpgv_verify "$keyring_path" "$signature_path" "$input_path" "failed to verify detached signature: $signature_path"; then
    /bin/rm -rf "$verify_home"
    return 1
  fi
  /bin/rm -rf "$verify_home"
}

release_trusted_gpg_fingerprints_csv() {
  local trusted=""
  local csv=""
  while IFS= read -r trusted; do
    [[ -n "$trusted" ]] || continue
    if [[ -n "$csv" ]]; then
      csv="$csv,$trusted"
    else
      csv="$trusted"
    fi
  done < <(release_trusted_gpg_fingerprints)
  printf '%s\n' "$csv"
}

release_import_trusted_public_key() {
  local public_key_path="$1"
  local verify_home="$2"
  release_trust_import_public_key_bundle "$public_key_path" "$verify_home" "$(release_trusted_gpg_fingerprints_csv)"
}
