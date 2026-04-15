#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./hasp-release-common.sh
source "$script_dir/hasp-release-common.sh"

usage() {
  cat <<'EOF'
Usage: hasp-uninstall-release.sh [--remove-hooks-from repo] [--purge-hasp-home path] <install-dir>

Remove a packaged HASP release tree. By default this removes the install tree only.
Hook cleanup and HASP_HOME deletion require explicit flags.
EOF
}

hook_repos=()
purge_hasp_home=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remove-hooks-from)
      hook_repos+=("$2")
      shift 2
      ;;
    --purge-hasp-home)
      purge_hasp_home="$2"
      shift 2
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

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 1
fi

install_dir_input="$1"
install_dir="$(release_abs_path "$install_dir_input")"
if [[ ! -d "$install_dir" ]]; then
  printf 'install directory not found: %s\n' "$install_dir" >&2
  exit 1
fi
release_require_manifest "$install_dir"

for repo_path in "${hook_repos[@]}"; do
  repo_path="$(release_abs_path "$repo_path")"
  if [[ ! -d "$repo_path/.git/hooks" ]]; then
    printf 'repo hooks directory not found: %s\n' "$repo_path" >&2
    exit 1
  fi
  for hook_name in pre-commit pre-push; do
    hook_path="$repo_path/.git/hooks/$hook_name"
    if [[ -f "$hook_path" ]] && { grep -q "HASP_ROOT_OVERRIDE=\"$install_dir\"" "$hook_path" || grep -q "HASP_ROOT_OVERRIDE=\"$install_dir_input\"" "$hook_path"; }; then
      /bin/rm -f "$hook_path"
    fi
  done
done

/bin/rm -rf "$install_dir"

if [[ -n "$purge_hasp_home" ]]; then
  purge_hasp_home="$(release_abs_path "$purge_hasp_home")"
  /bin/rm -rf "$purge_hasp_home"
fi
