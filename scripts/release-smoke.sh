#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"
# shellcheck source=./hasp-release-common.sh
source "$repo_root/scripts/hasp-release-common.sh"

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
tarball="$(bash ./scripts/package-release.sh)"
release_dir="$(cd "$(dirname "$tarball")" && pwd)"
install_root="$(mktemp -d)"
upgrade_root="$(mktemp -d)"
temp_home="$(mktemp -d)"
restore_home="$(mktemp -d)"
hook_repo="$(mktemp -d)"
protected_gpg_home="$(mktemp -d)"
protected_release_dir="$(mktemp -d)"
protected_public_dir="$(mktemp -d)"
protected_extract="$(mktemp -d)"
protected_passphrase_file="$(mktemp)"
installed_bin=""
chmod 700 "$protected_gpg_home"
cleanup_release_smoke() {
  stop_scoped_daemon "${installed_bin:-}" "$temp_home"
  stop_scoped_daemon "${installed_bin:-}" "$restore_home"
  /bin/rm -rf "$smoke_gpg_home" "$temp_home" "$restore_home" "$install_root" "$upgrade_root" "$hook_repo" "$protected_gpg_home" "$protected_release_dir" "$protected_public_dir" "$protected_extract"
  /bin/rm -f "$protected_passphrase_file"
}
trap cleanup_release_smoke EXIT

bash ./scripts/hasp-verify-release.sh "$tarball" >/dev/null
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
"$installed_bin" init >/dev/null
env_file="$temp_home/.env"
printf 'API_TOKEN=abc123\n' >"$env_file"
"$installed_bin" import "$env_file" >/dev/null
project_root="$temp_home/repo"
/bin/mkdir -p "$project_root"
git -C "$project_root" init >/dev/null 2>&1
"$installed_bin" bootstrap --profile claude-code --project-root "$project_root" --alias secret_01=API_TOKEN --hooks=false >/dev/null
"$installed_bin" project status --project-root "$project_root" >/dev/null
"$installed_bin" run \
  --project-root "$project_root" \
  --env API_TOKEN=secret_01 \
  --grant-project window \
  -- sh -c 'test "$API_TOKEN" = "abc123"' >/dev/null
env_output="$temp_home/.env.local"
"$installed_bin" write-env \
  --project-root "$project_root" \
  --output "$env_output" \
  --env API_TOKEN=secret_01 \
  --grant-project window \
  --grant-convenience window >/dev/null
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
  HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_FROM_API=1 brew uninstall --formula hasp >/dev/null 2>&1 || true
  HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_FROM_API=1 brew install --formula "$release_dir/Formula/hasp.rb" >/dev/null
  HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_FROM_API=1 brew test hasp >/dev/null
  HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_FROM_API=1 brew uninstall --formula hasp >/dev/null
fi
grep -q "url \"file://$tarball\"" "$release_dir/Formula/hasp.rb"
grep -q "sha256 \"$(release_sha256 "$tarball")\"" "$release_dir/Formula/hasp.rb"

protected_passphrase="release-smoke-gpg-passphrase"
printf '%s' "$protected_passphrase" >"$protected_passphrase_file"
chmod 600 "$protected_passphrase_file"
GNUPGHOME="$protected_gpg_home" gpg --batch --pinentry-mode loopback --passphrase "$protected_passphrase" \
  --quick-generate-key "HASP Protected Release Test Key <hasp@example.invalid>" ed25519 sign 1d >/dev/null 2>&1
protected_key_id="$(GNUPGHOME="$protected_gpg_home" gpg --batch --list-secret-keys --with-colons --fingerprint | awk -F: '/^fpr:/ {print $10; exit}')"
/bin/cp -f "$tarball" "$protected_release_dir/"
/usr/bin/tar -xzf "$tarball" -C "$protected_extract"
protected_tarball="$protected_release_dir/$(basename "$tarball")"
protected_artifact_dir="$protected_extract/$(basename "${tarball%.tar.gz}")"
HASP_RELEASE_GPG_HOMEDIR="$protected_gpg_home" \
HASP_RELEASE_GPG_KEY_ID="$protected_key_id" \
HASP_RELEASE_GPG_PASSPHRASE="$protected_passphrase" \
  bash ./scripts/hasp-sign-release.sh "$protected_artifact_dir" "$protected_tarball" >/dev/null
test -f "$protected_release_dir/SHA256SUMS.asc"
test -f "$protected_release_dir/$(basename "$tarball").asc"
test -f "$protected_release_dir/$(basename "${tarball%.tar.gz}")_bin.asc"
unset HASP_RELEASE_GPG_PASSPHRASE
for target in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64; do
  /bin/cp -f "$protected_tarball" "$protected_public_dir/hasp_${version}_${target}.tar.gz"
done
HASP_RELEASE_GPG_HOMEDIR="$protected_gpg_home" \
HASP_RELEASE_GPG_KEY_ID="$protected_key_id" \
HASP_RELEASE_GPG_PASSPHRASE_FILE="$protected_passphrase_file" \
  bash ./scripts/assemble-public-release.sh "$protected_public_dir" "https://example.invalid/hasp/releases/vtest" >/dev/null
test -f "$protected_public_dir/SHA256SUMS.asc"
grep -q 'https://example.invalid/hasp/releases/vtest/hasp_' "$protected_public_dir/release-metadata.json"
