#!/usr/bin/env bash
set -euo pipefail

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${HASP_TEST_ROOT:-}" ]]; then
  ROOT="$(cd "$HASP_TEST_ROOT" && pwd)"
elif [[ -f "$script_root/VERSION" && -f "$script_root/apps/server/go.mod" && ! -f "$script_root/scripts/export-public-hasp.py" ]]; then
  ROOT="$script_root"
elif ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  :
else
  ROOT="$script_root"
fi
# shellcheck source=./hasp-release-common.sh
source "$ROOT/scripts/hasp-release-common.sh"

tmp_dir="$(mktemp -d)"
cleanup() {
  /bin/rm -rf "$tmp_dir"
}
trap cleanup EXIT

assert_fails() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'expected failure: %s\n' "$label" >&2
    exit 1
  fi
}

cat >"$tmp_dir/metadata.env" <<'EOF'
version='1.0.0'
bad_value='hello world'
evil='$(touch /tmp/hasp-parser-should-not-run)'
EOF

test "$(release_metadata_scalar "$tmp_dir/metadata.env" version)" = "1.0.0"
assert_fails "metadata missing key" release_metadata_scalar "$tmp_dir/metadata.env" missing_key
assert_fails "metadata invalid value" release_metadata_scalar "$tmp_dir/metadata.env" bad_value
assert_fails "metadata invalid lookup key" release_metadata_scalar "$tmp_dir/metadata.env" "bad-key"
test ! -e /tmp/hasp-parser-should-not-run

trusted_home="$tmp_dir/trusted-home"
/bin/mkdir -p "$trusted_home"
chmod 700 "$trusted_home"
printf 'payload\n' >"$tmp_dir/payload"
cat >"$trusted_home/key.params" <<'EOF'
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: HASP Parser Test Key
Name-Email: hasp@example.invalid
Expire-Date: 1d
%no-protection
%transient-key
%commit
EOF
GNUPGHOME="$trusted_home" gpg --batch --no-tty --debug-quick-random --generate-key "$trusted_home/key.params" >/dev/null 2>&1
GNUPGHOME="$trusted_home" gpg --batch --armor --export >"$tmp_dir/public-key.asc"
GNUPGHOME="$trusted_home" gpg --batch --armor --detach-sign --output "$tmp_dir/payload.asc" "$tmp_dir/payload"
trusted_fingerprint="$(GNUPGHOME="$trusted_home" gpg --batch --list-keys --with-colons --fingerprint | awk -F: '/^fpr:/ {print $10; exit}')"
selected_fingerprint="$(
  GNUPGHOME="$trusted_home" \
    HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING=1 \
    HASP_RELEASE_GPG_KEY_ID="" \
    HASP_RELEASE_GPG_HOMEDIR="" \
    bash -c 'source "$1"; release_select_signing_key' bash "$ROOT/scripts/hasp-release-common.sh"
)"
test "$selected_fingerprint" = "$trusted_fingerprint"
# shellcheck disable=SC2016
assert_fails "invalid trusted fingerprint override" env HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS=not-a-fingerprint bash -c 'source "$1"; release_verify_detached_signature "$2" "$3" "$4"' bash \
  "$ROOT/scripts/hasp-release-common.sh" \
  "$tmp_dir/payload" \
  "$tmp_dir/payload.asc" \
  "$tmp_dir/public-key.asc"
# shellcheck disable=SC2016
assert_fails "ephemeral signing flag must not weaken verification trust" env HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING=1 HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS= bash -c 'source "$1"; release_verify_detached_signature "$2" "$3" "$4"' bash \
  "$ROOT/scripts/hasp-release-common.sh" \
  "$tmp_dir/payload" \
  "$tmp_dir/payload.asc" \
  "$tmp_dir/public-key.asc"
# shellcheck disable=SC2016
HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" bash -c 'source "$1"; release_verify_detached_signature "$2" "$3" "$4"' bash \
  "$ROOT/scripts/hasp-release-common.sh" \
  "$tmp_dir/payload" \
  "$tmp_dir/payload.asc" \
  "$tmp_dir/public-key.asc"

subkey_home="$tmp_dir/subkey-home"
/bin/mkdir -p "$subkey_home"
chmod 700 "$subkey_home"
cat >"$subkey_home/key.params" <<'EOF'
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: HASP Parser Subkey Test
Name-Email: hasp-subkey@example.invalid
Expire-Date: 1d
%no-protection
%transient-key
%commit
EOF
GNUPGHOME="$subkey_home" gpg --batch --no-tty --debug-quick-random --generate-key "$subkey_home/key.params" >/dev/null 2>&1
GNUPGHOME="$subkey_home" gpg --batch --armor --export >"$tmp_dir/subkey-public-key.asc"
GNUPGHOME="$subkey_home" gpg --batch --armor --detach-sign --output "$tmp_dir/subkey-payload.asc" "$tmp_dir/payload"
subkey_primary_fingerprint="$(GNUPGHOME="$subkey_home" gpg --batch --list-keys --with-colons --fingerprint | awk -F: '$1 == "pub" {want = 1; next} want && $1 == "fpr" {print $10; exit}')"
# shellcheck disable=SC2016
HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$subkey_primary_fingerprint" bash -c 'source "$1"; release_verify_detached_signature "$2" "$3" "$4"' bash \
  "$ROOT/scripts/hasp-release-common.sh" \
  "$tmp_dir/payload" \
  "$tmp_dir/subkey-payload.asc" \
  "$tmp_dir/subkey-public-key.asc"

# shellcheck disable=SC2016
assert_fails "ephemeral flag must not allow arbitrary untrusted signing key" env GNUPGHOME="$trusted_home" HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING=1 HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS= bash -c 'source "$1"; release_require_allowed_signing_fingerprint "$2" "release signing key"' bash \
  "$ROOT/scripts/hasp-release-common.sh" \
  "$trusted_fingerprint"

cat >"$tmp_dir/valid-manifest" <<'EOF'
release_files=(
  'bin/hasp'
  "scripts/hasp-verify-release.sh"
)
EOF
files=()
while IFS= read -r file; do
  files+=("$file")
done < <(release_manifest_files "$tmp_dir/valid-manifest")
test "${files[0]}" = "bin/hasp"
test "${files[1]}" = "scripts/hasp-verify-release.sh"

cat >"$tmp_dir/unquoted-manifest" <<'EOF'
release_files=(
  bin/hasp
)
EOF
assert_fails "manifest unquoted entry" release_manifest_files "$tmp_dir/unquoted-manifest"

cat >"$tmp_dir/absolute-manifest" <<'EOF'
release_files=(
  '/tmp/hasp'
)
EOF
assert_fails "manifest absolute path" release_manifest_files "$tmp_dir/absolute-manifest"

cat >"$tmp_dir/traversal-manifest" <<'EOF'
release_files=(
  '../hasp'
)
EOF
assert_fails "manifest traversal path" release_manifest_files "$tmp_dir/traversal-manifest"

cat >"$tmp_dir/dot-segment-manifest" <<'EOF'
release_files=(
  'bin/./hasp'
)
EOF
assert_fails "manifest dot-segment path" release_manifest_files "$tmp_dir/dot-segment-manifest"

cat >"$tmp_dir/missing-block" <<'EOF'
artifact_name_expected='hasp'
EOF
assert_fails "manifest missing release_files" release_manifest_files "$tmp_dir/missing-block"

/bin/mkdir -p "$tmp_dir/archive/root/bin"
printf 'payload\n' >"$tmp_dir/archive/root/bin/hasp"
release_tar -C "$tmp_dir/archive" -czf "$tmp_dir/valid.tar.gz" root
test "$(release_detect_topdir "$tmp_dir/valid.tar.gz")" = "root"
release_tar -xzf "$tmp_dir/valid.tar.gz" -C "$tmp_dir/archive"
release_validate_extracted_tree "$tmp_dir/archive/root"

/bin/mkdir -p "$tmp_dir/link-archive/root/bin"
ln -s /usr/bin/true "$tmp_dir/link-archive/root/bin/hasp"
release_tar -C "$tmp_dir/link-archive" -czf "$tmp_dir/link.tar.gz" root
assert_fails "archive symlink entry" release_detect_topdir "$tmp_dir/link.tar.gz"

/bin/mkdir -p "$tmp_dir/hardlink-archive/root/bin"
printf 'payload\n' >"$tmp_dir/hardlink-archive/root/bin/hasp"
ln "$tmp_dir/hardlink-archive/root/bin/hasp" "$tmp_dir/hardlink-archive/root/bin/hasp-hardlink"
release_tar -C "$tmp_dir/hardlink-archive" -czf "$tmp_dir/hardlink.tar.gz" root
assert_fails "archive hardlink entry" release_detect_topdir "$tmp_dir/hardlink.tar.gz"

printf 'release metadata parser checks passed\n'
