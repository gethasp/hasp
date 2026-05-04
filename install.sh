#!/usr/bin/env sh
set -eu

host="${HASP_DOWNLOAD_HOST:-https://download.gethasp.com}"
mirror="${HASP_RELEASE_BASE_URL:-https://downloads.gethasp.com/hasp/releases}"
trusted_fingerprints="${HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS:-1519745EA1129CF21EC3988DAF29D6911661DEE3}"
min_release_version="${HASP_RELEASE_MIN_VERSION:-1.0.0}"
bin_dir="${HASP_INSTALL_DIR:-$HOME/.local/bin}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required to install HASP" >&2
    exit 1
  fi
}

need awk
need bash
need curl
need gpg
need gpgv
need python3
need tar

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "$os" in
  darwin) os="darwin" ;;
  linux) os="linux" ;;
  *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac

case "$arch" in
  arm64|aarch64) arch="arm64" ;;
  x86_64|amd64) arch="amd64" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

make_temp_dir() {
  temp_parent="${HASP_INSTALL_TMPDIR:-${TMPDIR:-}}"
  if [ -n "$temp_parent" ]; then
    mkdir -p "$temp_parent"
    mktemp -d "$temp_parent/hi.XXXXXX"
    return 0
  fi
  mktemp -d
}

tmp="$(make_temp_dir)"
gpg_home="$tmp/gnupg"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT
mkdir -p "$gpg_home"
chmod 700 "$gpg_home"

metadata="$tmp/release-metadata.json"
metadata_sig="$tmp/release-metadata.json.asc"
public_key="$tmp/hasp-release-public-key.asc"

fetch_release_metadata() {
  metadata_url="$1"
  metadata_sig_url="$2"
  public_key_url="$3"
  log_prefix="$4"
  curl -fsSL "$metadata_url" -o "$metadata" 2>"$tmp/${log_prefix}-metadata.err" &&
    curl -fsSL "$metadata_sig_url" -o "$metadata_sig" 2>"$tmp/${log_prefix}-metadata-signature.err" &&
    curl -fsSL "$public_key_url" -o "$public_key" 2>"$tmp/${log_prefix}-public-key.err"
}

metadata_source=primary
if ! fetch_release_metadata "$host/api/release-metadata" "$host/api/release-metadata.asc" "$host/api/release-public-key.asc" primary; then
  if ! fetch_release_metadata "$mirror/latest/release-metadata.json" "$mirror/latest/release-metadata.json.asc" "$mirror/latest/hasp-release-public-key.asc" fallback; then
    echo "failed to fetch signed HASP release metadata from $host/api/release-metadata or $mirror/latest/release-metadata.json" >&2
    exit 1
  fi
  metadata_source=fallback
fi

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

verify_release_metadata_bundle() {
  release_trust_import_public_key_bundle "$public_key" "$gpg_home" "$trusted_fingerprints" &&
    gpgv --keyring "$release_trust_keyring_path" "$metadata_sig" "$metadata" >/dev/null 2>&1
}

if ! verify_release_metadata_bundle; then
  if [ "$metadata_source" = "primary" ] &&
    fetch_release_metadata "$mirror/latest/release-metadata.json" "$mirror/latest/release-metadata.json.asc" "$mirror/latest/hasp-release-public-key.asc" fallback; then
    metadata_source=fallback
    verify_release_metadata_bundle || {
      echo "failed to verify signed HASP release metadata from $mirror/latest/release-metadata.json" >&2
      exit 1
    }
  else
    echo "failed to verify signed HASP release metadata from $host/api/release-metadata" >&2
    exit 1
  fi
fi

metadata_vars="$(
  python3 - "$metadata" "$os" "$arch" "$mirror" "$min_release_version" <<'PY'
from datetime import datetime, timezone
import json
import os
import re
import shlex
import sys

metadata_path, wanted_os, wanted_arch, mirror, min_release_version = sys.argv[1:6]
with open(metadata_path, "r", encoding="utf-8") as handle:
    metadata = json.load(handle)

def version_sequence(value):
    match = re.fullmatch(r"([0-9]+)[.]([0-9]+)[.]([0-9]+)", value)
    if not match:
        raise SystemExit("release metadata version is invalid")
    major, minor, patch = (int(part) for part in match.groups())
    return major * 1_000_000 + minor * 1_000 + patch

def parse_timestamp(name):
    raw = str(metadata.get(name) or "").strip()
    if not raw:
        raise SystemExit(f"release metadata {name} is missing")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise SystemExit(f"release metadata {name} is invalid") from error
    if parsed.tzinfo is None:
        raise SystemExit(f"release metadata {name} must include a timezone")
    return parsed.astimezone(timezone.utc)

version = str(metadata.get("version") or "").strip()
if not re.fullmatch(r"[0-9]+[.][0-9]+[.][0-9]+", version):
    raise SystemExit("release metadata version is invalid")
expected_sequence = version_sequence(version)
min_sequence = version_sequence(min_release_version)
release_sequence = metadata.get("release_sequence")
if not isinstance(release_sequence, int) or release_sequence < 0:
    raise SystemExit("release metadata release_sequence is invalid")
if release_sequence != expected_sequence:
    raise SystemExit("release metadata release_sequence does not match version")
if release_sequence < min_sequence:
    raise SystemExit("release metadata sequence is older than this installer trusts")
issued_at = parse_timestamp("issued_at")
expires_at = parse_timestamp("expires_at")
now_raw = os.environ.get("HASP_RELEASE_METADATA_NOW", "").strip()
now = datetime.fromisoformat(now_raw.replace("Z", "+00:00")).astimezone(timezone.utc) if now_raw else datetime.now(timezone.utc)
if issued_at > expires_at:
    raise SystemExit("release metadata freshness window is invalid")
if now >= expires_at:
    raise SystemExit("release metadata has expired")
tag_base = str(metadata.get("tag_base_url") or f"{mirror.rstrip('/')}/v{version}").rstrip("/")
artifact_name = ""
for artifact in metadata.get("artifacts") or []:
    if artifact.get("os") == wanted_os and artifact.get("arch") == wanted_arch:
        artifact_name = str(artifact.get("name") or "")
        break
expected = f"hasp_{version}_{wanted_os}_{wanted_arch}"
if artifact_name != expected:
    raise SystemExit(f"release metadata did not include expected artifact {expected}")
https_url = re.fullmatch(r"https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+", tag_base)
local_test_url = re.fullmatch(
    r"http://(?:127[.]0[.]0[.]1|localhost)(?::[0-9]+)?/[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+",
    tag_base,
)
if not https_url and not (os.environ.get("HASP_ALLOW_LOCAL_INSTALL_TESTS") == "1" and local_test_url):
    raise SystemExit("release metadata tag_base_url is invalid")

print(f"version={shlex.quote(version)}")
print(f"tag_base={shlex.quote(tag_base)}")
print(f"artifact_name={shlex.quote(artifact_name)}")
PY
)" || exit 1
eval "$metadata_vars"

# shellcheck disable=SC2154
artifact="$tmp/$artifact_name.tar.gz"
# shellcheck disable=SC2154
curl -fsSL "$tag_base/$artifact_name.tar.gz" -o "$artifact"
curl -fsSL "$tag_base/SHA256SUMS" -o "$tmp/SHA256SUMS"
curl -fsSL "$tag_base/SHA256SUMS.asc" -o "$tmp/SHA256SUMS.asc"
curl -fsSL "$tag_base/$artifact_name.tar.gz.asc" -o "$tmp/$artifact_name.tar.gz.asc"
curl -fsSL "$tag_base/${artifact_name}_bin.asc" -o "$tmp/${artifact_name}_bin.asc"

gpgv --keyring "$release_trust_keyring_path" "$tmp/$artifact_name.tar.gz.asc" "$artifact" >/dev/null 2>&1

tar -xzf "$artifact" -C "$tmp" \
  "$artifact_name/scripts/hasp-release-common.sh" \
  "$artifact_name/scripts/hasp-verify-release.sh" \
  "$artifact_name/scripts/release-public-key-trust.sh" \
  "$artifact_name/scripts/release-trusted-gpg-fingerprints.txt"

artifact_root="$tmp/$artifact_name"
artifact_verifier="$artifact_root/scripts/hasp-verify-release.sh"
if [ ! -x "$artifact_verifier" ]; then
  echo "release verifier not found in release artifact" >&2
  exit 1
fi
HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprints" bash "$artifact_verifier" "$artifact" >/dev/null

tar -xzf "$artifact" -C "$tmp" "$artifact_name/bin/hasp"
hasp_bin="$artifact_root/bin/hasp"
if [ ! -f "$hasp_bin" ]; then
  echo "hasp binary not found in release artifact" >&2
  exit 1
fi

if [ -L "$bin_dir" ]; then
  echo "install directory must not be a symlink: $bin_dir" >&2
  exit 1
fi
mkdir -p "$bin_dir"
if [ -L "$bin_dir/hasp" ]; then
  echo "refusing to install through symlink: $bin_dir/hasp" >&2
  exit 1
fi
if [ -e "$bin_dir/hasp" ] && [ ! -f "$bin_dir/hasp" ]; then
  echo "refusing to replace non-file install target: $bin_dir/hasp" >&2
  exit 1
fi
python3 - "$hasp_bin" "$bin_dir" <<'PY'
import os
import secrets
import stat
import sys

source, bin_dir = sys.argv[1:3]
if os.path.islink(bin_dir):
    raise SystemExit(f"install directory must not be a symlink: {bin_dir}")

flags = os.O_RDONLY
flags |= getattr(os, "O_DIRECTORY", 0)
flags |= getattr(os, "O_NOFOLLOW", 0)
try:
    dir_fd = os.open(bin_dir, flags)
except OSError as error:
    raise SystemExit(f"failed to open install directory safely: {error}") from error

tmp_name = ""
try:
    try:
        existing = os.stat("hasp", dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if stat.S_ISLNK(existing.st_mode):
            raise SystemExit(f"refusing to install through symlink: {bin_dir}/hasp")
        if not stat.S_ISREG(existing.st_mode):
            raise SystemExit(f"refusing to replace non-file install target: {bin_dir}/hasp")

    for _ in range(16):
        candidate = f".hasp.{os.getpid()}.{secrets.token_hex(8)}"
        try:
            out_fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755, dir_fd=dir_fd)
            tmp_name = candidate
            break
        except FileExistsError:
            continue
    if not tmp_name:
        raise SystemExit("failed to allocate temporary install file")

    with open(source, "rb") as src, os.fdopen(out_fd, "wb") as out:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
        out.flush()
        os.fchmod(out.fileno(), 0o755)
        os.fsync(out.fileno())

    os.replace(tmp_name, "hasp", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    tmp_name = ""
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
finally:
    if tmp_name:
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
    os.close(dir_fd)
PY

echo "installed hasp to $bin_dir/hasp"
echo "next: hasp setup"
