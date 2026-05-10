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

assert_file() {
  local path="$1"
  if [[ ! -s "$path" ]]; then
    printf 'expected non-empty file: %s\n' "$path" >&2
    exit 1
  fi
}

# shellcheck disable=SC2016
env \
  HASP_RELEASE_BASE_URL="https://downloads.gethasp.com/hasp/releases" \
  bash -c 'source "$1"; release_require_publication_base "$HASP_RELEASE_BASE_URL"' bash "$ROOT/scripts/hasp-release-common.sh"

# shellcheck disable=SC2016
env \
  HASP_RELEASE_BASE_URL="https://github.com/gethasp/hasp/releases/download" \
  bash -c 'source "$1"; release_require_publication_base "$HASP_RELEASE_BASE_URL"' bash "$ROOT/scripts/hasp-release-common.sh"

# shellcheck disable=SC2016
assert_fails "publication base must be https" env \
  HASP_RELEASE_BASE_URL="http://downloads.gethasp.com/hasp/releases" \
  bash -c 'source "$1"; release_require_publication_base "$HASP_RELEASE_BASE_URL"' bash "$ROOT/scripts/hasp-release-common.sh"

if grep -Fq "\$repo_root/dist/release" "$ROOT/scripts/package-public-release.sh"; then
  printf 'package-public-release must not use shared dist/release scratch space\n' >&2
  exit 1
fi
grep -Fq "HASP_RELEASE_ROOT=\"\$target_release_root\"" "$ROOT/scripts/package-public-release.sh"
grep -Fq "HASP_PACKAGE_RELEASE_UNSIGNED=1" "$ROOT/scripts/package-public-release.sh"
# shellcheck disable=SC2016
grep -Fq 'bash ./scripts/build.sh -o "$artifact_dir/bin/hasp"' "$ROOT/scripts/package-release.sh"
# shellcheck disable=SC2016
if grep -Fq '$repo_root/bin/hasp' "$ROOT/scripts/package-release.sh"; then
  printf 'package-release must build directly into the artifact tree, not shared bin/hasp\n' >&2
  exit 1
fi
if [[ -f "$ROOT/scripts/reproducible-build.sh" ]] && grep -Fq 'buildVersion=' "$ROOT/scripts/reproducible-build.sh"; then
  printf 'reproducible-build must use the canonical runtime.Version ldflag path through build.sh\n' >&2
  exit 1
fi

version="$(<"$ROOT/VERSION")"
release_dir="$tmp_dir/public-release"
upgrade_signing_key="$tmp_dir/upgrade-signing-key"
gpg_home="$tmp_dir/gnupg"
/bin/mkdir -p "$gpg_home"
chmod 700 "$gpg_home"

(
  cd "$ROOT/apps/server"
  go run ./cmd/release-sign keygen --out "$upgrade_signing_key" >/dev/null
)
upgrade_pubkey="$(
  cd "$ROOT/apps/server"
  go run ./cmd/release-sign pubkey --key "$upgrade_signing_key"
)"

(
  cd "$ROOT"
  export GNUPGHOME="$gpg_home"
  export HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING=1
  export HASP_RELEASE_GPG_DEBUG_QUICK_RANDOM=1
	  export HASP_RELEASE_BASE_URL="https://github.com/gethasp/hasp/releases/download"
	  export HASP_TEAM_ID="${HASP_TEAM_ID:-UFV835UGV6}"
	  export HASP_UPGRADE_SIGNING_KEY_FILE="$upgrade_signing_key"
  export HASP_UPGRADE_TRUST_ROOTS_HEX="$upgrade_pubkey"
  unset HASP_RELEASE_GPG_KEY_ID
  unset HASP_RELEASE_GPG_HOMEDIR
  unset HASP_RELEASE_GPG_PASSPHRASE
  unset HASP_RELEASE_GPG_PASSPHRASE_FILE
  bash ./scripts/package-public-release.sh "v$version" "$release_dir" >/dev/null
)

assert_file "$release_dir/SHA256SUMS"
assert_file "$release_dir/SHA256SUMS.asc"
assert_file "$release_dir/hasp-release-public-key.asc"
assert_file "$release_dir/RELEASE-SIGNING-FINGERPRINT.txt"
assert_file "$release_dir/release-metadata.json"
assert_file "$release_dir/release-metadata.json.asc"
assert_file "$release_dir/KEYS-v$version"
assert_file "$release_dir/KEYS-v$version.sig"
assert_file "$release_dir/Formula/hasp.rb"

while read -r goos goarch _runner; do
  artifact="hasp_${version}_${goos}_${goarch}"
  assert_file "$release_dir/$artifact.tar.gz"
  assert_file "$release_dir/$artifact.tar.gz.asc"
  assert_file "$release_dir/${artifact}_bin.asc"
  assert_file "$release_dir/hasp-v${version}-${goos}-${goarch}.tar.gz"
  assert_file "$release_dir/hasp-v${version}-${goos}-${goarch}.tar.gz.sig"
  extract_dir="$tmp_dir/extract-$artifact"
  actual_files="$tmp_dir/$artifact.actual-files"
  listed_files="$tmp_dir/$artifact.manifest-files"
  /bin/mkdir -p "$extract_dir"
  bash -c 'source "$1"; shift; release_tar "$@"' bash "$ROOT/scripts/hasp-release-common.sh" -xzf "$release_dir/$artifact.tar.gz" -C "$extract_dir"
  (
    cd "$extract_dir/$artifact"
    find . -type f -print | sed 's#^\./##' | LC_ALL=C sort >"$actual_files"
  )
  bash -c 'source "$1"; release_manifest_files "$2"' bash \
    "$ROOT/scripts/hasp-release-common.sh" \
    "$extract_dir/$artifact/RELEASE_MANIFEST" |
    LC_ALL=C sort >"$listed_files"
  if ! diff -u "$listed_files" "$actual_files" >&2; then
    printf 'release manifest does not enumerate every packaged file for %s\n' "$artifact" >&2
    exit 1
  fi
done < <(python3 "$ROOT/scripts/release_targets.py" shell)

python3 "$ROOT/scripts/check_public_release_package.py" "$release_dir/release-metadata.json" "$version" "$ROOT/scripts/release-targets.json"

grep -q 'release-metadata.json' "$release_dir/SHA256SUMS"
grep -q 'release-metadata.json.asc' "$release_dir/SHA256SUMS"
grep -q 'hasp-v'"$version"'-linux-amd64.tar.gz.sig' "$release_dir/SHA256SUMS"

printf 'package public release checks passed\n'
