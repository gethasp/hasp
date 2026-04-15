#!/usr/bin/env bash
set -euo pipefail

release_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_repo_root="${HASP_ROOT_OVERRIDE:-$(cd "$release_script_dir/.." && pwd)}"
release_ephemeral_gnupghome=""

release_cleanup() {
  if [[ -n "$release_ephemeral_gnupghome" && -d "$release_ephemeral_gnupghome" ]]; then
    /bin/rm -rf "$release_ephemeral_gnupghome"
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

release_verify_checksums() {
  local manifest_path="$1"
  local manifest_dir
  manifest_dir="$(cd "$(dirname "$manifest_path")" && pwd)"
  local manifest_name
  manifest_name="$(basename "$manifest_path")"
  if command -v sha256sum >/dev/null 2>&1; then
    (
      cd "$manifest_dir"
      sha256sum -c "$manifest_name"
    )
    return 0
  fi
  (
    cd "$manifest_dir"
    shasum -a 256 -c "$manifest_name"
  )
}

release_detect_topdir() {
  local tarball="$1"
  local topdir=""
  local line=""
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
  done < <(/usr/bin/tar -tzf "$tarball")
  if [[ -z "$topdir" ]]; then
    printf 'release archive is empty: %s\n' "$tarball" >&2
    return 1
  fi
  printf '%s\n' "$topdir"
}

release_require_manifest() {
  local install_root="$1"
  if [[ ! -f "$install_root/RELEASE_MANIFEST" ]]; then
    printf 'install root is not a HASP release tree: %s\n' "$install_root" >&2
    return 1
  fi
}

release_list_secret_keys() {
  gpg --batch --list-secret-keys --with-colons --fingerprint 2>/dev/null | awk -F: '
    $1 == "fpr" { fingerprint = $10 }
    $1 == "uid" && fingerprint != "" { print fingerprint; fingerprint = "" }
  '
}

release_create_ephemeral_key() {
  release_ephemeral_gnupghome="$(mktemp -d)"
  chmod 700 "$release_ephemeral_gnupghome"
  GNUPGHOME="$release_ephemeral_gnupghome" gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "HASP Local Release Test Key <hasp@example.invalid>" ed25519 sign 1d >/dev/null 2>&1
  export GNUPGHOME="$release_ephemeral_gnupghome"
  release_list_secret_keys | head -n 1
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

  if [[ "${#keys[@]}" -eq 0 && "${HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING:-}" == "1" ]]; then
    release_create_ephemeral_key
    return 0
  fi

  if [[ "${#keys[@]}" -eq 0 ]]; then
    printf 'no GPG signing key found; set HASP_RELEASE_GPG_KEY_ID or HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING=1\n' >&2
    return 1
  fi

  printf 'multiple GPG secret keys found; set HASP_RELEASE_GPG_KEY_ID\n' >&2
  return 1
}

release_export_public_key() {
  local key_id="$1"
  local output_path="$2"
  gpg --batch --armor --export "$key_id" >"$output_path"
}

release_detached_sign() {
  local key_id="$1"
  local input_path="$2"
  local output_path="$3"
  gpg --batch --yes --armor --local-user "$key_id" --detach-sign --output "$output_path" "$input_path"
}

release_verify_signed_manifest() {
  local manifest_path="$1"
  local signature_path="$2"
  local public_key_path="$3"
  local verify_home
  verify_home="$(mktemp -d)"
  chmod 700 "$verify_home"
  if ! GNUPGHOME="$verify_home" gpg --batch --import "$public_key_path" >/dev/null 2>&1; then
    /bin/rm -rf "$verify_home"
    printf 'failed to import release public key: %s\n' "$public_key_path" >&2
    return 1
  fi
  if ! GNUPGHOME="$verify_home" gpg --batch --verify "$signature_path" "$manifest_path" >/dev/null 2>&1; then
    /bin/rm -rf "$verify_home"
    printf 'failed to verify signed checksum manifest: %s\n' "$manifest_path" >&2
    return 1
  fi
  /bin/rm -rf "$verify_home"
}

release_verify_detached_signature() {
  local input_path="$1"
  local signature_path="$2"
  local public_key_path="$3"
  local verify_home
  verify_home="$(mktemp -d)"
  chmod 700 "$verify_home"
  if ! GNUPGHOME="$verify_home" gpg --batch --import "$public_key_path" >/dev/null 2>&1; then
    /bin/rm -rf "$verify_home"
    printf 'failed to import release public key: %s\n' "$public_key_path" >&2
    return 1
  fi
  if ! GNUPGHOME="$verify_home" gpg --batch --verify "$signature_path" "$input_path" >/dev/null 2>&1; then
    /bin/rm -rf "$verify_home"
    printf 'failed to verify detached signature: %s\n' "$signature_path" >&2
    return 1
  fi
  /bin/rm -rf "$verify_home"
}
