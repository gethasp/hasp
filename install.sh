#!/usr/bin/env sh
set -eu

host="${HASP_DOWNLOAD_HOST:-https://download.gethasp.com}"
mirror="${HASP_RELEASE_BASE_URL:-https://downloads.gethasp.com/hasp/releases}"
trusted_fingerprints="${HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS:-1519745EA1129CF21EC3988DAF29D6911661DEE3}"
min_release_version="${HASP_RELEASE_MIN_VERSION:-1.0.0}"
bin_dir="${HASP_INSTALL_DIR:-$HOME/.local/bin}"

progress() {
  printf '==> %s\n' "$1"
}

has_tty() {
  ( : </dev/tty ) 2>/dev/null && ( : >/dev/tty ) 2>/dev/null
}

should_start_setup() {
  case "${HASP_INSTALL_RUN_SETUP:-}" in
    1|[Yy]|[Yy][Ee][Ss]|[Tt][Rr][Uu][Ee]) return 0 ;;
    0|[Nn]|[Nn][Oo]|[Ff][Aa][Ll][Ss][Ee]) return 1 ;;
    "") ;;
    *)
      printf 'ignoring invalid HASP_INSTALL_RUN_SETUP value: %s\n' "$HASP_INSTALL_RUN_SETUP" >&2
      return 1
      ;;
  esac

  if ! has_tty; then
    return 1
  fi

  printf 'Start hasp setup now? [Y/n] ' >/dev/tty
  IFS= read -r setup_answer </dev/tty || setup_answer=""
  case "$setup_answer" in
    ""|[Yy]|[Yy][Ee][Ss]) return 0 ;;
    *) return 1 ;;
  esac
}

run_setup_if_requested() {
  if should_start_setup; then
    progress "Starting hasp setup"
    if has_tty; then
      "$bin_dir/hasp" setup </dev/tty
    else
      "$bin_dir/hasp" setup
    fi
    return 0
  fi

  echo "next: hasp setup"
}

warn_path_resolution() {
  installed_path="$1"
  resolved_path="$(command -v hasp 2>/dev/null || true)"
  if [ -z "$resolved_path" ]; then
    printf 'warning: %s is not on PATH; add it or run %s directly\n' "$(dirname "$installed_path")" "$installed_path" >&2
    return 0
  fi

  path_status="$(
    python3 - "$installed_path" "$resolved_path" <<'PY'
import os
import sys

installed, resolved = sys.argv[1:3]
try:
    same = os.path.samefile(installed, resolved)
except OSError:
    same = os.path.abspath(installed) == os.path.abspath(resolved)
print("same" if same else "different")
PY
  )"
  if [ "$path_status" = "same" ]; then
    return 0
  fi

  printf 'warning: hasp on PATH resolves to %s, not the newly installed %s\n' "$resolved_path" "$installed_path" >&2
  printf 'warning: move %s earlier in PATH, remove the stale binary, then run hash -r in open shells\n' "$(dirname "$installed_path")" >&2
}

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required to install HASP" >&2
    exit 1
  fi
}

progress "Checking installer prerequisites"
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
progress "Detected $os/$arch"

make_temp_dir() {
  temp_parent="${HASP_INSTALL_TMPDIR:-${TMPDIR:-}}"
  if [ -n "$temp_parent" ]; then
    mkdir -p "$temp_parent"
    mktemp -d "$temp_parent/hi.XXXXXX"
    return 0
  fi
  mktemp -d
}

progress "Preparing temporary workspace"
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
progress "Fetching signed release metadata"
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
progress "Verified release metadata"

version=""
tag_base=""
artifact_name=""
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
progress "Selected HASP $version for $os/$arch"

artifact="$tmp/$artifact_name.tar.gz"
progress "Downloading release artifacts"
curl -fsSL "$tag_base/$artifact_name.tar.gz" -o "$artifact"
curl -fsSL "$tag_base/SHA256SUMS" -o "$tmp/SHA256SUMS"
curl -fsSL "$tag_base/SHA256SUMS.asc" -o "$tmp/SHA256SUMS.asc"
curl -fsSL "$tag_base/$artifact_name.tar.gz.asc" -o "$tmp/$artifact_name.tar.gz.asc"
curl -fsSL "$tag_base/${artifact_name}_bin.asc" -o "$tmp/${artifact_name}_bin.asc"

progress "Verifying release checksums and signatures"
if ! gpgv --keyring "$release_trust_keyring_path" "$tmp/SHA256SUMS.asc" "$tmp/SHA256SUMS" >/dev/null 2>&1; then
  echo "failed to verify release checksums signature" >&2
  exit 1
fi

checksum_paths="$tmp/SHA256SUMS.paths"
awk 'NF >= 2 { print $2 }' "$tmp/SHA256SUMS" >"$checksum_paths"
while IFS= read -r release_path; do
  [ -n "$release_path" ] || continue
  case "$release_path" in
    .|..|/*|./*|../*|*/../*|*/..|*"//"*|*\\*)
      echo "unsafe release checksum path: $release_path" >&2
      exit 1
      ;;
  esac
  case "$release_path" in
    SHA256SUMS|SHA256SUMS.asc|*.tar.gz|"$artifact_name"/*|hasp_*/bin/hasp|*/*)
      continue
      ;;
  esac
  curl -fsSL "$tag_base/$release_path" -o "$tmp/$release_path"
done <"$checksum_paths"

gpgv --keyring "$release_trust_keyring_path" "$tmp/$artifact_name.tar.gz.asc" "$artifact" >/dev/null 2>&1

artifact_root="$tmp/$artifact_name"
progress "Checking release archive"
python3 - "$tmp/SHA256SUMS" "$artifact" "$artifact_name" <<'PY'
import hashlib
import pathlib
import sys
import tarfile

checksums_path = pathlib.Path(sys.argv[1])
artifact_path = pathlib.Path(sys.argv[2])
artifact_name = sys.argv[3]
dist_dir = checksums_path.parent

checksums = {}
with checksums_path.open("r", encoding="utf-8") as handle:
    for line in handle:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        digest, relative_path = parts[0], parts[1]
        if len(digest) != 64 or any(char not in "0123456789abcdefABCDEF" for char in digest):
            raise SystemExit(f"invalid release checksum for {relative_path}")
        checksums[relative_path] = digest.lower()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_checksum(relative_path, target):
    expected = checksums.get(relative_path)
    if expected is None:
        raise SystemExit(f"release checksum entry missing: {relative_path}")
    if not target.is_file():
        raise SystemExit(f"release checksum target missing: {relative_path}")
    if sha256(target) != expected:
        raise SystemExit(f"release checksum mismatch for {relative_path}")


require_checksum(f"{artifact_name}.tar.gz", artifact_path)
for relative_path in sorted(checksums):
    if relative_path in {"SHA256SUMS", "SHA256SUMS.asc", f"{artifact_name}.tar.gz"}:
        continue
    if relative_path == f"{artifact_name}/bin/hasp":
        continue
    if relative_path.startswith(f"{artifact_name}/"):
        continue
    if relative_path.endswith(".tar.gz"):
        continue
    if relative_path.startswith("hasp_") and relative_path.endswith("/bin/hasp"):
        continue
    if "/" in relative_path:
        continue
    require_checksum(relative_path, dist_dir / relative_path)

with tarfile.open(artifact_path, "r:gz") as archive:
    members = archive.getmembers()
    names = {member.name for member in members}
    for member in members:
        name = member.name
        parts = pathlib.PurePosixPath(name).parts
        if (
            not parts
            or parts[0] != artifact_name
            or any(part in {"", ".", ".."} for part in parts)
            or name.startswith("/")
            or "//" in name
        ):
            raise SystemExit(f"unsafe archive entry: {name}")
        if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
            raise SystemExit("release archive contains unsupported link or special entries")
    for required in (
        "RELEASE_MANIFEST",
        "CODE_SIGNING_STATUS.json",
        "REPRODUCIBLE_BUILD.json",
        "sbom.spdx.json",
        "slsa-provenance.json",
        "bin/hasp",
    ):
        if f"{artifact_name}/{required}" not in names:
            raise SystemExit(f"release file missing from artifact: {required}")
PY

tar -xzf "$artifact" -C "$tmp" "$artifact_name/bin/hasp"
hasp_bin="$artifact_root/bin/hasp"
if [ ! -f "$hasp_bin" ]; then
  echo "hasp binary not found in release artifact" >&2
  exit 1
fi
progress "Verifying HASP binary"
if ! gpgv --keyring "$release_trust_keyring_path" "$tmp/${artifact_name}_bin.asc" "$hasp_bin" >/dev/null 2>&1; then
  echo "failed to verify HASP binary signature" >&2
  exit 1
fi
python3 - "$tmp/SHA256SUMS" "$hasp_bin" "$artifact_name/bin/hasp" <<'PY'
import hashlib
import pathlib
import sys

checksums_path = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
relative_path = sys.argv[3]
expected = ""
with checksums_path.open("r", encoding="utf-8") as handle:
    for line in handle:
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1] == relative_path:
            expected = parts[0].lower()
            break
if not expected:
    raise SystemExit(f"release checksum entry missing: {relative_path}")
digest = hashlib.sha256()
with target.open("rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest() != expected:
    raise SystemExit(f"release checksum mismatch for {relative_path}")
PY

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
progress "Installing to $bin_dir/hasp"
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
installed_version="$("$bin_dir/hasp" version 2>/dev/null || true)"
if [ -n "$installed_version" ]; then
  printf 'version: %s\n' "$installed_version"
else
  printf 'version: %s\n' "$version"
fi
warn_path_resolution "$bin_dir/hasp"
run_setup_if_requested
