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

PRIVATE_INSTALLER="$ROOT/apps/web/src/public/install.sh"
PUBLIC_INSTALLER="$ROOT/public/install.sh"
INSTALLER="$PRIVATE_INSTALLER"
if [[ -f "$PRIVATE_INSTALLER" && -f "$PUBLIC_INSTALLER" ]] && ! cmp -s "$PRIVATE_INSTALLER" "$PUBLIC_INSTALLER"; then
  printf 'public installer copy is stale: %s differs from %s\n' "$PUBLIC_INSTALLER" "$PRIVATE_INSTALLER" >&2
  exit 1
fi
if [[ ! -f "$INSTALLER" ]]; then
  INSTALLER="$ROOT/install.sh"
fi

/bin/mkdir -p "$ROOT/dist"
test_tmp_parent="${TMPDIR:-/tmp}"
tmp_dir="$(mktemp -d "$test_tmp_parent/hpi.XXXXXX")"
/bin/mkdir -p "$tmp_dir/tmp" "$tmp_dir/install-tmp" "$tmp_dir/release-tmp"
export TMPDIR="$tmp_dir/tmp"
export HASP_INSTALL_TMPDIR="$tmp_dir/install-tmp"
export HASP_RELEASE_TMPDIR="$tmp_dir/release-tmp"
server_pid=""
cleanup() {
  if command -v pkill >/dev/null 2>&1; then
    for home in "$tmp_dir/trusted-gnupg" "$tmp_dir/attacker-gnupg"; do
      if [[ -d "$home" ]]; then
        pkill -f "gpg-agent --homedir $home" >/dev/null 2>&1 || true
        pkill -f "scdaemon .*--homedir $home" >/dev/null 2>&1 || true
      fi
    done
  fi
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  /bin/rm -rf "$tmp_dir" || true
}
trap cleanup EXIT

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return 0
  fi
  shasum -a 256 "$1" | awk '{print $1}'
}

release_sequence() {
  local version="$1"
  local major=""
  local minor=""
  local patch=""
  IFS=. read -r major minor patch <<<"$version"
  printf '%s\n' "$((10#$major * 1000000 + 10#$minor * 1000 + 10#$patch))"
}

make_key() {
  local home="$1"
  local uid="$2"
  local name="$uid"
  local email="hasp-test@example.invalid"
  local key_params="$home/key.params"
  /bin/mkdir -p "$home"
  chmod 700 "$home"
  if [[ "$uid" == *"<"*">" ]]; then
    name="${uid%% <*}"
    email="${uid#*<}"
    email="${email%>*}"
  fi
  printf '%s\n' \
    'Key-Type: eddsa' \
    'Key-Curve: ed25519' \
    'Key-Usage: sign' \
    "Name-Real: $name" \
    "Name-Email: $email" \
    'Expire-Date: 1d' \
    '%no-protection' \
    '%transient-key' \
    '%commit' >"$key_params"
  GNUPGHOME="$home" gpg --batch --no-tty --debug-quick-random --generate-key "$key_params" >/dev/null 2>&1
  GNUPGHOME="$home" gpg --batch --list-secret-keys --with-colons --fingerprint |
    awk -F: '/^fpr:/ {print $10; exit}'
}

detect_os() {
  case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
    darwin) printf 'darwin\n' ;;
    linux) printf 'linux\n' ;;
    *) printf 'unsupported OS\n' >&2; return 1 ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    arm64|aarch64) printf 'arm64\n' ;;
    x86_64|amd64) printf 'amd64\n' ;;
    *) printf 'unsupported architecture\n' >&2; return 1 ;;
  esac
}

start_server() {
  local root="$1"
  local port_file="$2"
  local log_file="$3"
  python3 - "$root" "$port_file" >"$log_file" 2>&1 <<'PY' &
import functools
import http.server
import socketserver
import sys

root, port_file = sys.argv[1:3]
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=root)

class Server(socketserver.TCPServer):
    allow_reuse_address = True

with Server(("127.0.0.1", 0), handler) as httpd:
    with open(port_file, "w", encoding="utf-8") as handle:
        handle.write(str(httpd.server_address[1]))
    httpd.serve_forever()
PY
  server_pid="$!"
  for _ in $(seq 1 50); do
    [[ -s "$port_file" ]] && return 0
    sleep 0.1
  done
  cat "$log_file" >&2 || true
  printf 'test HTTP server did not start\n' >&2
  return 1
}

write_metadata_bundle() {
  local signer_home="$1"
  local public_key_path="$2"
  local server_root="$3"
  local metadata_json="$4"

  /bin/mkdir -p "$server_root/api" "$server_root/latest"
  printf '%s\n' "$metadata_json" >"$server_root/api/release-metadata"
  printf '%s\n' "$metadata_json" >"$server_root/api/release"
  printf '%s\n' "$metadata_json" >"$server_root/latest/release-metadata.json"
  GNUPGHOME="$signer_home" gpg --batch --yes --armor --detach-sign --output "$server_root/api/release-metadata.asc" "$server_root/api/release-metadata"
  /bin/cp -f "$server_root/api/release-metadata.asc" "$server_root/latest/release-metadata.json.asc"
  /bin/cp -f "$public_key_path" "$server_root/api/release-public-key.asc"
  /bin/cp -f "$public_key_path" "$server_root/latest/hasp-release-public-key.asc"
}

write_release() {
  local signer_home="$1"
  local public_key_path="$2"
  local server_root="$3"
  local base_url="$4"
  local version="$5"
  local os_name="$6"
  local arch_name="$7"
  local archive_mode="${8:-regular}"
  local artifact_name="hasp_${version}_${os_name}_${arch_name}"
  local tag_dir="$server_root/v$version"
  local build_dir="$tmp_dir/build"

  /bin/rm -rf "$tag_dir" "$build_dir"
  /bin/mkdir -p "$tag_dir" "$server_root/api" "$server_root/latest" "$build_dir/$artifact_name/bin" "$build_dir/$artifact_name/scripts"
  if [[ "$archive_mode" == "symlink" ]]; then
    ln -s /usr/bin/true "$build_dir/$artifact_name/bin/hasp"
  else
    cat >"$build_dir/$artifact_name/bin/hasp" <<'SH'
#!/usr/bin/env sh
echo hasp-test
SH
    chmod +x "$build_dir/$artifact_name/bin/hasp"
    if [[ "$archive_mode" == "hardlink" ]]; then
      ln "$build_dir/$artifact_name/bin/hasp" "$build_dir/$artifact_name/bin/hasp-hardlink"
    fi
  fi
  cat >"$build_dir/$artifact_name/RELEASE_MANIFEST" <<EOF
artifact_name_expected='$artifact_name'
version='$version'
release_files=(
  'RELEASE_MANIFEST'
  'CODE_SIGNING_STATUS.json'
  'REPRODUCIBLE_BUILD.json'
  'sbom.spdx.json'
  'slsa-provenance.json'
  'bin/hasp'
)
EOF
  printf '{}\n' >"$build_dir/$artifact_name/CODE_SIGNING_STATUS.json"
  printf '{}\n' >"$build_dir/$artifact_name/REPRODUCIBLE_BUILD.json"
  printf '{}\n' >"$build_dir/$artifact_name/sbom.spdx.json"
  printf '{}\n' >"$build_dir/$artifact_name/slsa-provenance.json"
  /bin/cp -f "$ROOT/scripts/hasp-release-common.sh" "$build_dir/$artifact_name/scripts/hasp-release-common.sh"
  /bin/cp -f "$ROOT/scripts/hasp-verify-release.sh" "$build_dir/$artifact_name/scripts/hasp-verify-release.sh"
  /bin/cp -f "$ROOT/scripts/release-public-key-trust.sh" "$build_dir/$artifact_name/scripts/release-public-key-trust.sh"
  /bin/cp -f "$ROOT/scripts/release-trusted-gpg-fingerprints.txt" "$build_dir/$artifact_name/scripts/release-trusted-gpg-fingerprints.txt"
  chmod +x "$build_dir/$artifact_name/scripts/hasp-release-common.sh" "$build_dir/$artifact_name/scripts/hasp-verify-release.sh" "$build_dir/$artifact_name/scripts/release-public-key-trust.sh"
  tar -C "$build_dir" -czf "$tag_dir/$artifact_name.tar.gz" "$artifact_name"
  /bin/cp -f "$public_key_path" "$tag_dir/hasp-release-public-key.asc"
  {
    printf '%s  %s\n' "$(sha256 "$tag_dir/$artifact_name.tar.gz")" "$artifact_name.tar.gz"
    printf '%s  %s\n' "$(sha256 "$build_dir/$artifact_name/bin/hasp")" "$artifact_name/bin/hasp"
  } >"$tag_dir/SHA256SUMS"
  GNUPGHOME="$signer_home" gpg --batch --yes --armor --detach-sign --output "$tag_dir/SHA256SUMS.asc" "$tag_dir/SHA256SUMS"
  GNUPGHOME="$signer_home" gpg --batch --yes --armor --detach-sign --output "$tag_dir/$artifact_name.tar.gz.asc" "$tag_dir/$artifact_name.tar.gz"
  GNUPGHOME="$signer_home" gpg --batch --yes --armor --detach-sign --output "$tag_dir/${artifact_name}_bin.asc" "$build_dir/$artifact_name/bin/hasp"
  metadata_json="$(
    cat <<EOF
{"version":"$version","release_sequence":$(release_sequence "$version"),"issued_at":"2026-04-30T00:00:00Z","expires_at":"2999-01-01T00:00:00Z","tag_base_url":"$base_url/v$version","artifacts":[{"os":"$os_name","arch":"$arch_name","name":"$artifact_name"}]}
EOF
  )"
  write_metadata_bundle "$signer_home" "$public_key_path" "$server_root" "$metadata_json"
}

assert_installer_fails() {
  local label="$1"
  shift
  local log="$tmp_dir/${label//[^A-Za-z0-9_]/_}.log"
  if "$@" >"$log" 2>&1; then
    printf 'expected installer failure: %s\n' "$label" >&2
    cat "$log" >&2
    exit 1
  fi
  printf '%s\n' "$log"
}

assert_log_contains() {
  local log="$1"
  local pattern="$2"
  if ! grep -q "$pattern" "$log"; then
    printf 'expected log %s to contain: %s\n' "$log" "$pattern" >&2
    cat "$log" >&2
    exit 1
  fi
}

assert_log_matches() {
  local log="$1"
  local pattern="$2"
  if ! grep -Eq "$pattern" "$log"; then
    printf 'expected log %s to match: %s\n' "$log" "$pattern" >&2
    cat "$log" >&2
    exit 1
  fi
}

version="$(sed 's/^v//' "$ROOT/VERSION")"
os_name="$(detect_os)"
arch_name="$(detect_arch)"
artifact_name="hasp_${version}_${os_name}_${arch_name}"
server_root="$tmp_dir/server"
/bin/mkdir -p "$server_root"
port_file="$tmp_dir/http.port"
start_server "$server_root" "$port_file" "$tmp_dir/http.log"
base_url="http://127.0.0.1:$(cat "$port_file")"

trusted_home="$tmp_dir/trusted-gnupg"
attacker_home="$tmp_dir/attacker-gnupg"
trusted_fingerprint="$(make_key "$trusted_home" "HASP Installer Trusted Test <hasp-trusted@example.invalid>")"
make_key "$attacker_home" "HASP Installer Attacker Test <hasp-attacker@example.invalid>" >/dev/null
trusted_public="$tmp_dir/trusted-public.asc"
attacker_public="$tmp_dir/attacker-public.asc"
mixed_public="$tmp_dir/mixed-public.asc"
GNUPGHOME="$trusted_home" gpg --batch --armor --export >"$trusted_public"
GNUPGHOME="$attacker_home" gpg --batch --armor --export >"$attacker_public"
cat "$trusted_public" "$attacker_public" >"$mixed_public"

write_release "$attacker_home" "$mixed_public" "$server_root" "$base_url" "$version" "$os_name" "$arch_name"
if HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" bash "$ROOT/scripts/hasp-verify-release.sh" "$server_root/v$version/$artifact_name.tar.gz" >/dev/null 2>&1; then
  printf 'shared verifier accepted mixed public key bundle\n' >&2
  exit 1
fi
mixed_log="$(assert_installer_fails "mixed public key bundle" env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  HASP_INSTALL_DIR="$tmp_dir/mixed-bin" \
  sh "$INSTALLER")"
assert_log_contains "$mixed_log" 'release public key bundle must contain exactly one primary key'
test ! -e "$tmp_dir/mixed-bin/hasp"

write_release "$trusted_home" "$trusted_public" "$server_root" "$base_url" "$version" "$os_name" "$arch_name"
HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" bash "$ROOT/scripts/hasp-verify-release.sh" "$server_root/v$version/$artifact_name.tar.gz" >/dev/null

/bin/rm -f "$server_root/api/release-metadata.asc" "$server_root/latest/release-metadata.json.asc"
unsigned_metadata_log="$(assert_installer_fails "unsigned release metadata" env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url" \
  HASP_RELEASE_BASE_URL="$base_url" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  HASP_INSTALL_DIR="$tmp_dir/unsigned-metadata-bin" \
  sh "$INSTALLER")"
assert_log_contains "$unsigned_metadata_log" 'failed to fetch signed HASP release metadata'
write_release "$trusted_home" "$trusted_public" "$server_root" "$base_url" "$version" "$os_name" "$arch_name"

GNUPGHOME="$attacker_home" gpg --batch --yes --armor --detach-sign --output "$server_root/api/release-metadata.asc" "$server_root/api/release-metadata"
/bin/cp -f "$server_root/api/release-metadata.asc" "$server_root/latest/release-metadata.json.asc"
assert_installer_fails "bad metadata signature" env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url" \
  HASP_RELEASE_BASE_URL="$base_url" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  HASP_INSTALL_DIR="$tmp_dir/bad-metadata-signature-bin" \
  sh "$INSTALLER" >/dev/null
write_release "$trusted_home" "$trusted_public" "$server_root" "$base_url" "$version" "$os_name" "$arch_name"

bad_tag_metadata="{\"version\":\"$version\",\"release_sequence\":$(release_sequence "$version"),\"issued_at\":\"2026-04-30T00:00:00Z\",\"expires_at\":\"2999-01-01T00:00:00Z\",\"tag_base_url\":\"http://evil.example/hasp/releases/v$version\",\"artifacts\":[{\"os\":\"$os_name\",\"arch\":\"$arch_name\",\"name\":\"$artifact_name\"}]}"
write_metadata_bundle "$trusted_home" "$trusted_public" "$server_root" "$bad_tag_metadata"
bad_tag_log="$(assert_installer_fails "bad tag base url" env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  HASP_INSTALL_DIR="$tmp_dir/bad-tag-bin" \
  sh "$INSTALLER")"
assert_log_contains "$bad_tag_log" 'release metadata tag_base_url is invalid'
write_release "$trusted_home" "$trusted_public" "$server_root" "$base_url" "$version" "$os_name" "$arch_name"

old_version="0.999.999"
old_artifact_name="hasp_${old_version}_${os_name}_${arch_name}"
rollback_metadata="{\"version\":\"$old_version\",\"release_sequence\":$(release_sequence "$old_version"),\"issued_at\":\"2026-04-30T00:00:00Z\",\"expires_at\":\"2999-01-01T00:00:00Z\",\"tag_base_url\":\"$base_url/v$old_version\",\"artifacts\":[{\"os\":\"$os_name\",\"arch\":\"$arch_name\",\"name\":\"$old_artifact_name\"}]}"
write_metadata_bundle "$trusted_home" "$trusted_public" "$server_root" "$rollback_metadata"
rollback_log="$(assert_installer_fails "rollback release metadata" env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  HASP_INSTALL_DIR="$tmp_dir/rollback-bin" \
  sh "$INSTALLER")"
assert_log_contains "$rollback_log" 'release metadata sequence is older than this installer trusts'
write_release "$trusted_home" "$trusted_public" "$server_root" "$base_url" "$version" "$os_name" "$arch_name"

expired_metadata="{\"version\":\"$version\",\"release_sequence\":$(release_sequence "$version"),\"issued_at\":\"2026-04-01T00:00:00Z\",\"expires_at\":\"2026-04-02T00:00:00Z\",\"tag_base_url\":\"$base_url/v$version\",\"artifacts\":[{\"os\":\"$os_name\",\"arch\":\"$arch_name\",\"name\":\"$artifact_name\"}]}"
write_metadata_bundle "$trusted_home" "$trusted_public" "$server_root" "$expired_metadata"
expired_log="$(assert_installer_fails "expired release metadata" env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url" \
  HASP_RELEASE_METADATA_NOW="2026-05-01T00:00:00Z" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  HASP_INSTALL_DIR="$tmp_dir/expired-bin" \
  sh "$INSTALLER")"
assert_log_contains "$expired_log" 'release metadata has expired'
write_release "$trusted_home" "$trusted_public" "$server_root" "$base_url" "$version" "$os_name" "$arch_name"

printf 'corrupt\n' >>"$server_root/v$version/SHA256SUMS"
assert_installer_fails "corrupt checksum signature" env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  HASP_INSTALL_DIR="$tmp_dir/corrupt-checksum-bin" \
  sh "$INSTALLER" >/dev/null
write_release "$trusted_home" "$trusted_public" "$server_root" "$base_url" "$version" "$os_name" "$arch_name" symlink
link_archive_log="$(assert_installer_fails "symlink archive entry" env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  HASP_INSTALL_DIR="$tmp_dir/link-archive-bin" \
  sh "$INSTALLER")"
assert_log_matches "$link_archive_log" 'release archive contains unsupported link or special entries|unsafe archive link entry'
write_release "$trusted_home" "$trusted_public" "$server_root" "$base_url" "$version" "$os_name" "$arch_name" hardlink
hardlink_archive_log="$(assert_installer_fails "hardlink archive entry" env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  HASP_INSTALL_DIR="$tmp_dir/hardlink-archive-bin" \
  sh "$INSTALLER")"
assert_log_matches "$hardlink_archive_log" 'release archive contains unsupported link or special entries|unsafe archive link entry'
write_release "$trusted_home" "$trusted_public" "$server_root" "$base_url" "$version" "$os_name" "$arch_name"

default_trust_root="$(tr -d '[:space:]' <"$ROOT/scripts/release-trusted-gpg-fingerprints.txt")"
if [[ ! "$default_trust_root" =~ ^[0-9A-F]{40}$ ]]; then
  printf 'default release trust root is not a single uppercase GPG fingerprint: %s\n' "$default_trust_root" >&2
  exit 1
fi
extract_trust_block() {
  sed -n '/^# BEGIN HASP_RELEASE_PUBLIC_KEY_TRUST$/,/^# END HASP_RELEASE_PUBLIC_KEY_TRUST$/p' "$1"
}
helper_trust_block="$(extract_trust_block "$ROOT/scripts/release-public-key-trust.sh")"
for trust_consumer in "$INSTALLER" "$PUBLIC_INSTALLER" "$ROOT/scripts/hasp-release-common.sh"; do
  [[ -f "$trust_consumer" ]] || continue
  if [[ "$trust_consumer" == *"hasp-release-common.sh" ]]; then
    grep -q 'release-public-key-trust.sh' "$trust_consumer"
    continue
  fi
  if [[ "$(extract_trust_block "$trust_consumer")" != "$helper_trust_block" ]]; then
    printf 'release public-key trust helper drifted in %s\n' "$trust_consumer" >&2
    exit 1
  fi
done
# shellcheck disable=SC2016
installer_trust_root="$(sed -nE 's/^trusted_fingerprints="\$\{HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS:-([0-9A-F]+)\}"$/\1/p' "$INSTALLER")"
common_trust_root="$(sed -nE 's/^release_default_trusted_gpg_fingerprints="([0-9A-F]+)"$/\1/p' "$ROOT/scripts/hasp-release-common.sh")"
if [[ "$installer_trust_root" != "$default_trust_root" || "$common_trust_root" != "$default_trust_root" ]]; then
  printf 'release trust roots drifted: installer=%s common=%s file=%s\n' "$installer_trust_root" "$common_trust_root" "$default_trust_root" >&2
  exit 1
fi
if [[ -f "$PRIVATE_INSTALLER" ]]; then
  grep -q "$default_trust_root" "$PRIVATE_INSTALLER"
fi
if [[ -f "$PUBLIC_INSTALLER" ]]; then
  grep -q "$default_trust_root" "$PUBLIC_INSTALLER"
fi
grep -q 'release-trusted-gpg-fingerprints.txt' "$ROOT/scripts/hasp-release-common.sh"
default_installer="$tmp_dir/install-default-trust-root.sh"
sed "s/$default_trust_root/$trusted_fingerprint/g" "$INSTALLER" >"$default_installer"
chmod +x "$default_installer"
default_bin_dir="$tmp_dir/default-trust-bin"
env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS= \
  HASP_INSTALL_DIR="$default_bin_dir" \
  sh "$default_installer" >/dev/null
test -x "$default_bin_dir/hasp"

bin_dir="$tmp_dir/bin"
victim="$tmp_dir/victim"
/bin/mkdir -p "$bin_dir"
printf 'sentinel\n' >"$victim"
ln -s "$victim" "$bin_dir/hasp"
symlink_log="$(assert_installer_fails "symlink install target" env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  HASP_INSTALL_DIR="$bin_dir" \
  sh "$INSTALLER")"
assert_log_contains "$symlink_log" 'refusing to install through symlink'
grep -qx 'sentinel' "$victim"

/bin/rm -f "$bin_dir/hasp"
env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  HASP_INSTALL_DIR="$bin_dir" \
  sh "$INSTALLER" >/dev/null
test -x "$bin_dir/hasp"
test "$("$bin_dir/hasp")" = "hasp-test"

fallback_bin_dir="$tmp_dir/fallback-bin"
/bin/rm -f "$server_root/api/release-metadata" "$server_root/api/release-metadata.asc" "$server_root/api/release-public-key.asc"
env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url/missing-api-host" \
  HASP_RELEASE_BASE_URL="$base_url" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  HASP_INSTALL_DIR="$fallback_bin_dir" \
  sh "$INSTALLER" >/dev/null
test -x "$fallback_bin_dir/hasp"

/bin/rm -f "$server_root/latest/release-metadata.json" "$server_root/latest/release-metadata.json.asc" "$server_root/latest/hasp-release-public-key.asc"
missing_metadata_log="$(assert_installer_fails "missing release metadata" env \
  HASP_ALLOW_LOCAL_INSTALL_TESTS=1 \
  HASP_DOWNLOAD_HOST="$base_url/missing-api-host" \
  HASP_RELEASE_BASE_URL="$base_url/missing-mirror" \
  HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  HASP_INSTALL_DIR="$tmp_dir/missing-metadata-bin" \
  sh "$INSTALLER")"
assert_log_contains "$missing_metadata_log" 'failed to fetch signed HASP release metadata'

printf 'public installer checks passed\n'
