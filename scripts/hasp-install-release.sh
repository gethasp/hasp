#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./hasp-release-common.sh
source "$script_dir/hasp-release-common.sh"

usage() {
  cat <<'EOF'
Usage: hasp-install-release.sh [--verify|--no-verify] <release-tarball> [install-dir]

Install a packaged HASP release tarball into a local prefix.
EOF
}

verify_release=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify)
      verify_release=1
      shift
      ;;
    --no-verify)
      verify_release=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      printf 'unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage >&2
  exit 1
fi

reject_symlinked_path_parent() {
  local target="$1"
  local parent
  parent="$(dirname "$target")"
  local current=""
  local rest=""
  if [[ "$parent" == /* ]]; then
    current="/"
    rest="${parent#/}"
  else
    current="$(pwd -P)"
    rest="$parent"
  fi

  local old_ifs="$IFS"
  IFS="/"
  read -r -a parts <<<"$rest"
  IFS="$old_ifs"

  local part=""
  for part in "${parts[@]}"; do
    [[ -n "$part" && "$part" != "." ]] || continue
    if [[ "$part" == ".." ]]; then
      current="$(dirname "$current")"
      continue
    fi
    if [[ "$current" == "/" ]]; then
      current="/$part"
    else
      current="$current/$part"
    fi
    if [[ -L "$current" ]]; then
      if release_is_allowed_system_symlink_parent "$current"; then
        continue
      fi
      printf 'refusing to install through symlinked parent: %s\n' "$current" >&2
      return 1
    fi
    if [[ -e "$current" && ! -d "$current" ]]; then
      printf 'install parent component is not a directory: %s\n' "$current" >&2
      return 1
    fi
  done
}

release_is_allowed_system_symlink_parent() {
  local current="$1"
  [[ "$(uname -s)" == "Darwin" ]] || return 1

  local link_target=""
  link_target="$(readlink "$current" 2>/dev/null || true)"
  case "$current:$link_target" in
    /tmp:private/tmp|/tmp:/private/tmp|/var:private/var|/var:/private/var)
      return 0
      ;;
  esac
  return 1
}

tarball="$(release_abs_path "$1")"
install_dir_input="${2:-$HOME/.local/share/hasp/$(basename "${tarball%.tar.gz}")}"
if [[ -L "$install_dir_input" ]]; then
  printf 'refusing to install over symlink: %s\n' "$install_dir_input" >&2
  exit 1
fi
reject_symlinked_path_parent "$install_dir_input"
install_dir="$(release_abs_path "$install_dir_input")"

if [[ ! -f "$tarball" ]]; then
  printf 'release tarball not found: %s\n' "$tarball" >&2
  exit 1
fi

source_tarball="$tarball"
stage_input_dir="$(mktemp -d)"
if [[ "$verify_release" -eq 1 ]]; then
  tarball="$(release_stage_tarball_with_sidecars "$source_tarball" "$stage_input_dir")"
else
  tarball="$(release_private_tarball_copy "$source_tarball" "$stage_input_dir")"
fi

if [[ "$verify_release" -eq 1 ]]; then
  bash "$script_dir/hasp-verify-release.sh" "$tarball"
fi

topdir="$(release_detect_topdir "$tarball")"
tmp_dir="$(mktemp -d)"
install_parent="$(dirname "$install_dir")"
install_name="$(basename "$install_dir")"
/bin/mkdir -p "$install_parent"
stage_parent="$(mktemp -d "$install_parent/.${install_name}.staging.XXXXXXXX")"
backup_parent="$(mktemp -d "$install_parent/.${install_name}.backup.XXXXXXXX")"
stage_dir="$stage_parent/$install_name"
backup_dir="$backup_parent/$install_name"

cleanup() {
  /bin/rm -rf "$tmp_dir" "$stage_parent" "$backup_parent" "$stage_input_dir"
}
trap cleanup EXIT

release_tar -xzf "$tarball" -C "$tmp_dir"
artifact_dir="$tmp_dir/$topdir"
if [[ ! -d "$artifact_dir" ]]; then
  printf 'release tarball did not contain the expected top-level directory: %s\n' "$topdir" >&2
  exit 1
fi
release_validate_extracted_tree "$artifact_dir"
release_require_manifest "$artifact_dir"

if [[ -L "$install_dir" ]]; then
  printf 'refusing to install over symlink: %s\n' "$install_dir" >&2
  exit 1
fi
/bin/cp -R "$artifact_dir" "$stage_dir"
manifest_path="$stage_dir/RELEASE_MANIFEST"
release_version="$(release_metadata_scalar "$manifest_path" version)"
artifact_name_expected="$(release_metadata_scalar "$manifest_path" artifact_name_expected)"
cat >"$stage_dir/INSTALL_RECEIPT" <<EOF
installed_version='${release_version}'
artifact_name='${artifact_name_expected}'
source_tarball='${source_tarball}'
installed_at='$(date -u +%Y-%m-%dT%H:%M:%SZ)'
EOF

if [[ -e "$install_dir" ]]; then
  if [[ -d "$install_dir" ]] && [[ -z "$(/bin/ls -A "$install_dir")" ]]; then
    /bin/rm -rf "$install_dir"
  else
    release_require_manifest "$install_dir"
    /bin/rm -rf "$backup_dir"
    /bin/mv "$install_dir" "$backup_dir"
  fi
fi

if ! /bin/mv "$stage_dir" "$install_dir"; then
  if [[ -d "$backup_dir" ]]; then
    /bin/mv "$backup_dir" "$install_dir"
  fi
  printf 'failed to install release into %s\n' "$install_dir" >&2
  exit 1
fi

if [[ -d "$backup_dir" ]]; then
  /bin/rm -rf "$backup_dir"
fi

"$install_dir/bin/hasp" version >/dev/null
printf '%s\n' "$install_dir"
