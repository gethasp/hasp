#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
# shellcheck source=./hasp-release-common.sh
source "$repo_root/scripts/hasp-release-common.sh"

usage() {
  cat <<'EOF'
Usage: release-smoke.sh [--target <goos>/<goarch>] [--release-dir <dir>]

Build, verify, install, and exercise a release tarball for the current host.
When --target is provided, it must match the native host runtime because this
smoke test executes the packaged binary.
When --release-dir is provided, smoke the already-packaged tarball from that
directory instead of building a throwaway local package.
EOF
}

host_goos="$(go env GOHOSTOS)"
host_goarch="$(go env GOHOSTARCH)"
target_goos="$host_goos"
target_goarch="$host_goarch"
existing_release_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      if [[ "${2:-}" != */* ]]; then
        usage >&2
        exit 2
      fi
      target_goos="${2%%/*}"
      target_goarch="${2#*/}"
      shift 2
      ;;
    --release-dir)
      if [[ -z "${2:-}" ]]; then
        usage >&2
        exit 2
      fi
      existing_release_dir="$(release_abs_path "$2")"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if ! python3 "$repo_root/scripts/release_targets.py" has-target "$target_goos/$target_goarch"; then
  echo "unsupported release smoke target: $target_goos/$target_goarch" >&2
  exit 2
fi

if [[ "$target_goos/$target_goarch" != "$host_goos/$host_goarch" ]]; then
  echo "release smoke target $target_goos/$target_goarch must run on matching host $host_goos/$host_goarch" >&2
  exit 2
fi

export GOOS="$target_goos"
export GOARCH="$target_goarch"

stop_scoped_daemon() {
  local bin_path="$1"
  local hasp_home="$2"
  local socket_path="${3:-}"
  [[ -n "$hasp_home" ]] || return 0

  local pid_file="$hasp_home/runtime/daemon.pid"
  local effective_socket="$socket_path"
  local pid=""
  local verified_pid=""
  if [[ -z "$effective_socket" ]]; then
    effective_socket="$hasp_home/runtime/daemon.sock"
  fi
  if [[ -f "$pid_file" ]]; then
    pid="$(tr -d '[:space:]' <"$pid_file" 2>/dev/null || true)"
    if pid_matches_scoped_daemon "$pid" "$effective_socket"; then
      verified_pid="$pid"
    fi
  fi

  if [[ -n "$verified_pid" && -x "$bin_path" ]]; then
    env HASP_HOME="$hasp_home" HASP_SOCKET="$effective_socket" "$bin_path" daemon stop >/dev/null 2>&1 || true
  fi

  if [[ -n "$verified_pid" ]]; then
    kill "$verified_pid" >/dev/null 2>&1 || true
    sleep 1
    kill -9 "$verified_pid" >/dev/null 2>&1 || true
  fi

  /bin/rm -f "$pid_file" "$effective_socket"
}

pid_matches_scoped_daemon() {
  local pid="$1"
  local socket_path="$2"
  [[ -n "$pid" && -n "$socket_path" ]] || return 1

  local command=""
  command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
  [[ "$command" == *" daemon serve"* ]] || return 1
  command -v lsof >/dev/null 2>&1 || return 1
  lsof -a -p "$pid" -U -Fn 2>/dev/null | grep -F "n$socket_path" >/dev/null 2>&1
}

version="$(< VERSION)"
smoke_gpg_home="$(mktemp -d)"
chmod 700 "$smoke_gpg_home"
export GNUPGHOME="$smoke_gpg_home"
unset HASP_RELEASE_GPG_KEY_ID
unset HASP_RELEASE_GPG_HOMEDIR
unset HASP_RELEASE_GPG_PASSPHRASE
unset HASP_RELEASE_GPG_PASSPHRASE_FILE
export HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING=1
export HASP_RELEASE_GPG_DEBUG_QUICK_RANDOM=1
upgrade_signing_key="$(mktemp)"
metadata_probe="$(mktemp -d)"
(
  cd "$repo_root/apps/server"
  go run ./cmd/release-sign keygen --out "$upgrade_signing_key" >/dev/null
)
export HASP_UPGRADE_SIGNING_KEY_FILE="$upgrade_signing_key"
upgrade_trust_roots_hex="$(
  cd "$repo_root/apps/server"
  go run ./cmd/release-sign pubkey --key "$upgrade_signing_key"
)"
export HASP_UPGRADE_TRUST_ROOTS_HEX="$upgrade_trust_roots_hex"
if [[ -n "$existing_release_dir" ]]; then
  release_dir="$existing_release_dir"
  tarball="$release_dir/hasp_${version}_${target_goos}_${target_goarch}.tar.gz"
  if [[ ! -d "$release_dir" ]]; then
    echo "release smoke directory not found: $release_dir" >&2
    exit 1
  fi
  if [[ ! -f "$tarball" ]]; then
    echo "release smoke tarball not found: $tarball" >&2
    exit 1
  fi
else
  tarball="$(bash ./scripts/package-release.sh)"
  release_dir="$(cd "$(dirname "$tarball")" && pwd)"
fi
install_root="$(mktemp -d)"
upgrade_root="$(mktemp -d)"
temp_home="$(mktemp -d)"
restore_home="$(mktemp -d)"
hook_repo="$(mktemp -d)"
protected_gpg_home="$(mktemp -d)"
protected_release_dir="$(mktemp -d)"
protected_public_dir="$(mktemp -d)"
protected_extract="$(mktemp -d)"
attacker_gpg_home="$(mktemp -d)"
attacker_release_dir="$(mktemp -d)"
installer_symlink_probe="$(mktemp -d)"
installer_staging_probe="$(mktemp -d)"
protected_passphrase_file="$(mktemp)"
trusted_key_file="$(mktemp)"
installed_bin=""
chmod 700 "$protected_gpg_home"
chmod 700 "$attacker_gpg_home"
cleanup_release_smoke() {
  stop_scoped_daemon "${installed_bin:-}" "$temp_home"
  stop_scoped_daemon "${installed_bin:-}" "$restore_home"
  /bin/rm -rf "$smoke_gpg_home" "$metadata_probe" "$temp_home" "$restore_home" "$install_root" "$upgrade_root" "$hook_repo" "$protected_gpg_home" "$protected_release_dir" "$protected_public_dir" "$protected_extract" "$attacker_gpg_home" "$attacker_release_dir" "$installer_symlink_probe" "$installer_staging_probe"
  /bin/rm -f "$protected_passphrase_file" "$upgrade_signing_key" "$trusted_key_file"
}
trap cleanup_release_smoke EXIT

export HASP_RELEASE_METADATA_PWNED="$metadata_probe/pwned"
cat >"$metadata_probe/RELEASE_MANIFEST" <<'EOF'
artifact_name_expected='metadata_probe'
version='0.0.0-test'
release_files=(
  'bin/hasp'
)
touch "$HASP_RELEASE_METADATA_PWNED"
EOF
test "$(release_metadata_scalar "$metadata_probe/RELEASE_MANIFEST" artifact_name_expected)" = "metadata_probe"
test "$(release_metadata_scalar "$metadata_probe/RELEASE_MANIFEST" version)" = "0.0.0-test"
release_manifest_files "$metadata_probe/RELEASE_MANIFEST" | grep -qx 'bin/hasp'
test ! -e "$HASP_RELEASE_METADATA_PWNED"
cat >"$metadata_probe/INSTALL_RECEIPT" <<'EOF'
installed_version='0.0.0-test'
touch "$HASP_RELEASE_METADATA_PWNED"
EOF
test "$(release_metadata_scalar "$metadata_probe/INSTALL_RECEIPT" installed_version)" = "0.0.0-test"
test ! -e "$HASP_RELEASE_METADATA_PWNED"

printf 'attacker payload\n' >"$attacker_release_dir/payload"
trusted_public_key="$attacker_release_dir/trusted-public-key.asc"
attacker_public_key="$attacker_release_dir/attacker-public-key.asc"
cat >"$attacker_gpg_home/key.params" <<'EOF'
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: HASP Attacker Release Key
Name-Email: attacker@example.invalid
Expire-Date: 1d
%no-protection
%transient-key
%commit
EOF
GNUPGHOME="$attacker_gpg_home" gpg --batch --no-tty --debug-quick-random --generate-key "$attacker_gpg_home/key.params" >/dev/null 2>&1
release_select_signing_key >"$trusted_key_file"
trusted_key_id="$(<"$trusted_key_file")"
release_export_public_key "$trusted_key_id" "$trusted_public_key"
GNUPGHOME="$attacker_gpg_home" gpg --batch --armor --export >"$attacker_public_key"
GNUPGHOME="$attacker_gpg_home" gpg --batch --armor --detach-sign --output "$attacker_release_dir/payload.asc" "$attacker_release_dir/payload"
# shellcheck disable=SC2016
if env -u HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING -u HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS \
  bash -c 'source "$1"; release_verify_detached_signature "$2" "$3" "$4"' bash \
  "$repo_root/scripts/hasp-release-common.sh" \
  "$attacker_release_dir/payload" \
  "$attacker_release_dir/payload.asc" \
  "$attacker_public_key"; then
  echo "attacker-generated release key was trusted" >&2
  exit 1
fi
# shellcheck disable=SC2016
if env HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING=1 HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS= \
  bash -c 'source "$1"; release_verify_detached_signature "$2" "$3" "$4"' bash \
  "$repo_root/scripts/hasp-release-common.sh" \
  "$attacker_release_dir/payload" \
  "$attacker_release_dir/payload.asc" \
  "$attacker_public_key"; then
  echo "attacker-generated release key was trusted" >&2
  exit 1
fi
cat "$trusted_public_key" "$attacker_public_key" >"$attacker_release_dir/mixed-public-key.asc"
trusted_fingerprint="$(release_signing_fingerprint "$trusted_key_id")"
# shellcheck disable=SC2016
if HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$trusted_fingerprint" \
  bash -c 'source "$1"; release_verify_detached_signature "$2" "$3" "$4"' bash \
  "$repo_root/scripts/hasp-release-common.sh" \
  "$attacker_release_dir/payload" \
  "$attacker_release_dir/payload.asc" \
  "$attacker_release_dir/mixed-public-key.asc"; then
  echo "mixed trusted+attacker release key bundle was trusted" >&2
  exit 1
fi

HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$(cat "$release_dir/RELEASE-SIGNING-FINGERPRINT.txt")"
export HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS
bash ./scripts/hasp-verify-release.sh "$tarball" >/dev/null

symlink_victim="$installer_symlink_probe/victim"
symlink_install="$installer_symlink_probe/install-link"
/bin/mkdir -p "$symlink_victim"
/bin/ln -s "$symlink_victim" "$symlink_install"
if bash ./scripts/hasp-install-release.sh --no-verify "$tarball" "$symlink_install" >/dev/null 2>&1; then
  echo "installer accepted a symlink install target" >&2
  exit 1
fi
if [[ -n "$(find "$symlink_victim" -mindepth 1 -print -quit)" ]]; then
  echo "installer wrote through a symlink install target" >&2
  exit 1
fi

symlink_parent_real="$installer_symlink_probe/real-parent"
symlink_parent_link="$installer_symlink_probe/link-parent"
/bin/mkdir -p "$symlink_parent_real"
/bin/ln -s "$symlink_parent_real" "$symlink_parent_link"
if bash ./scripts/hasp-install-release.sh --no-verify "$tarball" "$symlink_parent_link/hasp" >/dev/null 2>&1; then
  echo "installer accepted a symlinked install parent" >&2
  exit 1
fi
if [[ -n "$(find "$symlink_parent_real" -mindepth 1 -print -quit)" ]]; then
  echo "installer wrote through a symlinked install parent" >&2
  exit 1
fi

staging_parent="$installer_staging_probe/parent"
staging_victim="$installer_staging_probe/victim"
staging_install="$staging_parent/hasp"
/bin/mkdir -p "$staging_parent" "$staging_victim"
if ! bash -c 'set -euo pipefail; install_dir="$1"; tarball="$2"; victim="$3"; /bin/ln -s "$victim" "${install_dir}.staging.$$"; exec bash ./scripts/hasp-install-release.sh --no-verify "$tarball" "$install_dir"' bash "$staging_install" "$tarball" "$staging_victim" >/dev/null; then
  echo "installer failed with a preexisting predictable staging symlink" >&2
  exit 1
fi
test -x "$staging_install/bin/hasp"
if [[ -n "$(find "$staging_victim" -mindepth 1 -print -quit)" ]]; then
  echo "installer followed a predictable staging symlink" >&2
  exit 1
fi

bash ./scripts/hasp-install-release.sh --verify "$tarball" "$install_root" >/dev/null
installed_bin="$install_root/bin/hasp"

export HASP_HOME="$temp_home"
export HASP_MASTER_PASSWORD="release-smoke-password"
export HASP_BACKUP_PASSPHRASE="release-smoke-backup"

test -f "$release_dir/SHA256SUMS"
test -f "$release_dir/SHA256SUMS.asc"
test -f "$release_dir/hasp-release-public-key.asc"
test -f "$release_dir/$(basename "$tarball").asc"
test -f "$release_dir/$(basename "${tarball%.tar.gz}")_bin.asc"
test -f "$release_dir/Formula/hasp.rb"
if [[ -f "$release_dir/Casks/hasp.rb" ]]; then
  bash ./scripts/homebrew-cask-smoke.sh "$release_dir/Casks/hasp.rb"
fi
test -f "$install_root/RELEASE_MANIFEST"
test -f "$install_root/sbom.spdx.json"
test -f "$install_root/slsa-provenance.json"
test -f "$install_root/CODE_SIGNING_STATUS.json"
test -f "$install_root/REPRODUCIBLE_BUILD.json"
test -f "$install_root/INSTALL_RECEIPT"
test -x "$install_root/scripts/hasp-install-release.sh"
test -x "$install_root/scripts/hasp-upgrade-release.sh"
test -x "$install_root/scripts/hasp-uninstall-release.sh"
test -x "$install_root/scripts/hasp-verify-release.sh"
grep -q 'verify the tarball' "$install_root/README.md"
grep -q 'hasp-verify-release.sh' "$install_root/QUICKSTART.md"
grep -q 'hasp-upgrade-release.sh' "$install_root/QUICKSTART.md"
grep -q 'stages a new release tree' "$install_root/OPERATOR_GUIDE.md"

"$installed_bin" version >/dev/null
"$installed_bin" version --json | grep -q '"upgrade_trust_roots":true'
"$installed_bin" init >/dev/null
env_file="$temp_home/.env"
printf 'API_TOKEN=abc123\n' >"$env_file"
"$installed_bin" import "$env_file" >/dev/null
project_root="$temp_home/repo"
/bin/mkdir -p "$project_root"
git -C "$project_root" init >/dev/null 2>&1
"$installed_bin" bootstrap --profile claude-code --project-root "$project_root" --alias secret_01=API_TOKEN --hooks=false >/dev/null
"$installed_bin" project status --project-root "$project_root" >/dev/null
# shellcheck disable=SC2016
"$installed_bin" run \
  --project-root "$project_root" \
  --env API_TOKEN=@API_TOKEN \
  --grant-project window \
  --grant-window 15m \
  -- sh -c 'test "$API_TOKEN" = "abc123"' >/dev/null
env_output="$temp_home/.env.local"
"$installed_bin" write-env \
  --project-root "$project_root" \
  --output "$env_output" \
  --env API_TOKEN=@API_TOKEN \
  --grant-project window \
  --grant-convenience window \
  --grant-window 15m >/dev/null
grep -q 'API_TOKEN=abc123' "$env_output"
backup_path="$temp_home/hasp.backup.json"
"$installed_bin" export-backup --output "$backup_path" >/dev/null
"$installed_bin" audit >/dev/null

HASP_HOME="$restore_home" HASP_MASTER_PASSWORD="restored-release-password" HASP_BACKUP_PASSPHRASE="$HASP_BACKUP_PASSPHRASE" "$installed_bin" restore-backup --input "$backup_path" >/dev/null
HASP_HOME="$restore_home" HASP_MASTER_PASSWORD="restored-release-password" "$installed_bin" audit >/dev/null

bash ./scripts/hasp-install-release.sh --verify "$tarball" "$upgrade_root/current" >/dev/null
bash ./scripts/hasp-upgrade-release.sh --verify "$tarball" "$upgrade_root/current" >/dev/null
test -x "$upgrade_root/current/bin/hasp"
grep -q '^previous_version=' "$upgrade_root/current/INSTALL_RECEIPT"

/bin/mkdir -p "$hook_repo"
git -C "$hook_repo" init >/dev/null 2>&1
(
  cd "$hook_repo"
  HASP_ROOT_OVERRIDE="$install_root" bash "$install_root/scripts/hasp-install-hooks.sh" >/dev/null
)
test -f "$hook_repo/.git/hooks/pre-commit"
bash ./scripts/hasp-uninstall-release.sh --remove-hooks-from "$hook_repo" "$install_root" >/dev/null
test ! -d "$install_root"
test -d "$temp_home"
test ! -f "$hook_repo/.git/hooks/pre-commit"

if command -v ruby >/dev/null 2>&1; then
  ruby -c "$release_dir/Formula/hasp.rb" >/dev/null
fi
if [[ "${HASP_RUN_BREW_INSTALL_SMOKE:-0}" == "1" ]] && command -v brew >/dev/null 2>&1; then
  bash ./scripts/homebrew-formula-smoke.sh "$release_dir/Formula/hasp.rb"
fi
if [[ -n "$existing_release_dir" ]]; then
  grep -q "hasp_${version}_${target_goos}_${target_goarch}.tar.gz" "$release_dir/Formula/hasp.rb"
else
  grep -q "url \"file://$tarball\"" "$release_dir/Formula/hasp.rb"
fi
grep -q "sha256 \"$(release_sha256 "$tarball")\"" "$release_dir/Formula/hasp.rb"

protected_passphrase="release-smoke-gpg-passphrase"
printf '%s' "$protected_passphrase" >"$protected_passphrase_file"
chmod 600 "$protected_passphrase_file"
cat >"$protected_gpg_home/key.params" <<'EOF'
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: HASP Protected Release Test Key
Name-Email: hasp@example.invalid
Expire-Date: 1d
%transient-key
%commit
EOF
GNUPGHOME="$protected_gpg_home" gpg --batch --no-tty --debug-quick-random --pinentry-mode loopback --passphrase "$protected_passphrase" --generate-key "$protected_gpg_home/key.params" >/dev/null 2>&1
protected_key_id="$(GNUPGHOME="$protected_gpg_home" gpg --batch --list-secret-keys --with-colons --fingerprint | awk -F: '/^fpr:/ {print $10; exit}')"
/bin/cp -f "$tarball" "$protected_release_dir/"
release_tar -xzf "$tarball" -C "$protected_extract"
protected_tarball="$protected_release_dir/$(basename "$tarball")"
protected_artifact_dir="$protected_extract/$(basename "${tarball%.tar.gz}")"
HASP_RELEASE_GPG_HOMEDIR="$protected_gpg_home" \
HASP_RELEASE_GPG_KEY_ID="$protected_key_id" \
HASP_RELEASE_GPG_PASSPHRASE="$protected_passphrase" \
HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$protected_key_id" \
  bash ./scripts/hasp-sign-release.sh "$protected_artifact_dir" "$protected_tarball" >/dev/null
test -f "$protected_release_dir/SHA256SUMS.asc"
test -f "$protected_release_dir/$(basename "$tarball").asc"
test -f "$protected_release_dir/$(basename "${tarball%.tar.gz}")_bin.asc"
unset HASP_RELEASE_GPG_PASSPHRASE
	while read -r goos goarch _runner; do
	  /bin/cp -f "$protected_tarball" "$protected_public_dir/hasp_${version}_${goos}_${goarch}.tar.gz"
	done < <(python3 scripts/release_targets.py shell)
HASP_RELEASE_GPG_HOMEDIR="$protected_gpg_home" \
HASP_RELEASE_GPG_KEY_ID="$protected_key_id" \
HASP_RELEASE_GPG_PASSPHRASE_FILE="$protected_passphrase_file" \
HASP_RELEASE_TRUSTED_GPG_FINGERPRINTS="$protected_key_id" \
  bash ./scripts/assemble-public-release.sh "$protected_public_dir" "https://example.invalid/hasp/releases/vtest" >/dev/null
test -f "$protected_public_dir/SHA256SUMS.asc"
test -f "$protected_public_dir/release-metadata.json.asc"
GNUPGHOME="$protected_gpg_home" gpg --batch --verify "$protected_public_dir/release-metadata.json.asc" "$protected_public_dir/release-metadata.json" >/dev/null 2>&1
grep -q 'release-metadata.json' "$protected_public_dir/SHA256SUMS"
grep -q 'https://example.invalid/hasp/releases/vtest/hasp_' "$protected_public_dir/release-metadata.json"
