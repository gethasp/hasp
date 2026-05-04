# shellcheck shell=sh
# BEGIN HASP_RELEASE_PUBLIC_KEY_TRUST
release_trust_normalize_fingerprint() {
  printf '%s' "$1" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]'
}

release_trust_fingerprint_is_valid() {
  release_trust_valid_candidate="$1"
  if [ "${#release_trust_valid_candidate}" -ne 40 ]; then
    return 1
  fi
  case "$release_trust_valid_candidate" in
    *[!0123456789ABCDEF]*) return 1 ;;
  esac
}

release_trust_fingerprint_is_trusted() {
  release_trust_candidate="$(release_trust_normalize_fingerprint "$1")"
  release_trust_fingerprint_is_valid "$release_trust_candidate" || return 1

  release_trust_old_ifs="$IFS"
  IFS=","
  for release_trust_fingerprint in $2; do
    release_trust_normalized="$(release_trust_normalize_fingerprint "$release_trust_fingerprint")"
    if [ -z "$release_trust_normalized" ]; then
      continue
    fi
    if ! release_trust_fingerprint_is_valid "$release_trust_normalized"; then
      IFS="$release_trust_old_ifs"
      printf 'invalid trusted release GPG fingerprint: %s\n' "$release_trust_fingerprint" >&2
      return 2
    fi
    if [ "$release_trust_candidate" = "$release_trust_normalized" ]; then
      IFS="$release_trust_old_ifs"
      return 0
    fi
  done
  IFS="$release_trust_old_ifs"
  return 1
}

release_trust_import_public_key_bundle() {
  release_trust_public_key_path="$1"
  release_trust_verify_home="$2"
  release_trust_trusted_fingerprints="$3"
  release_trust_key_info="$release_trust_verify_home/public-key-info"
  release_trust_keyring_path="$release_trust_verify_home/release-public-key.gpg"
  release_trust_dearmor_error="$release_trust_verify_home/public-key-dearmor.err"

  if ! GNUPGHOME="$release_trust_verify_home" gpg --batch --with-colons --import-options show-only --import "$release_trust_public_key_path" 2>/dev/null >"$release_trust_key_info"; then
    printf 'failed to inspect release public key: %s\n' "$release_trust_public_key_path" >&2
    return 1
  fi

  release_trust_primary_count="$(awk -F: '$1 == "pub" {count++} END {print count + 0}' "$release_trust_key_info")"
  release_trust_primary_fingerprint="$(awk -F: '$1 == "pub" {want = 1; next} want && $1 == "fpr" {print $10; exit}' "$release_trust_key_info")"
  if [ -z "$release_trust_primary_fingerprint" ]; then
    printf 'failed to read release public key fingerprint: %s\n' "$release_trust_public_key_path" >&2
    return 1
  fi
  if [ "$release_trust_primary_count" != "1" ]; then
    printf 'release public key bundle must contain exactly one primary key, got %s\n' "$release_trust_primary_count" >&2
    return 1
  fi

  release_trust_status=0
  release_trust_fingerprint_is_trusted "$release_trust_primary_fingerprint" "$release_trust_trusted_fingerprints" || release_trust_status=$?
  if [ "$release_trust_status" -eq 2 ]; then
    return 2
  fi
  if [ "$release_trust_status" -ne 0 ]; then
    printf 'release public key is not a trusted HASP signer: %s\n' "$release_trust_primary_fingerprint" >&2
    return 1
  fi

  if ! gpg --batch --yes --dearmor --output "$release_trust_keyring_path" "$release_trust_public_key_path" >/dev/null 2>"$release_trust_dearmor_error"; then
    printf 'failed to prepare release public keyring: %s\n' "$release_trust_public_key_path" >&2
    sed 's/^/gpg: /' "$release_trust_dearmor_error" >&2
    return 1
  fi
}
# END HASP_RELEASE_PUBLIC_KEY_TRUST
