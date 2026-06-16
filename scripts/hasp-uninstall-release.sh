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

git_hardened() (
  unset GIT_DIR GIT_WORK_TREE GIT_CONFIG GIT_CONFIG_GLOBAL GIT_CONFIG_COUNT
  GIT_TERMINAL_PROMPT=0 \
    GIT_PAGER=cat \
    GIT_OPTIONAL_LOCKS=0 \
    GIT_CONFIG_SYSTEM=/dev/null \
    LC_ALL=C \
    git "$@"
)

physical_path() {
  local input="$1"
  local probe
  if [[ "$input" = /* ]]; then
    probe="$input"
  else
    probe="$PWD/$input"
  fi

  local -a missing=()
  while [[ ! -e "$probe" ]]; do
    missing=("$(basename "$probe")" "${missing[@]}")
    local parent
    parent="$(dirname "$probe")"
    if [[ "$parent" == "$probe" ]]; then
      return 1
    fi
    probe="$parent"
  done

  local resolved
  if [[ -d "$probe" ]]; then
    resolved="$(cd "$probe" && pwd -P)"
  else
    local probe_dir
    local probe_base
    probe_dir="$(dirname "$probe")"
    probe_base="$(basename "$probe")"
    resolved="$(cd "$probe_dir" && pwd -P)/$probe_base"
  fi
  local part
  for part in "${missing[@]}"; do
    resolved="$resolved/$part"
  done
  printf '%s\n' "$resolved"
}

path_is_child() {
  local child="$1"
  local parent="$2"
  [[ "$child" != "$parent" && "$child"/ == "$parent"/* ]]
}

resolve_repo_hooks_dir() {
  local repo_path="$1"
  if ! git_hardened -c core.hooksPath=/dev/null -c safe.directory='*' -C "$repo_path" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf 'not a git working tree: %s\n' "$repo_path" >&2
    return 1
  fi

  local project_root
  local common_dir
  local hooks_path=""
  local hooks_dir
  local has_hooks_path=0
  project_root="$(git_hardened -c core.hooksPath=/dev/null -c safe.directory='*' -C "$repo_path" rev-parse --show-toplevel)"
  common_dir="$(git_hardened -c core.hooksPath=/dev/null -c safe.directory='*' -C "$repo_path" rev-parse --path-format=absolute --git-common-dir)"
  if hooks_path="$(git_hardened -c safe.directory='*' -C "$repo_path" config --path --get core.hooksPath 2>/dev/null)"; then
    has_hooks_path=1
  else
    local rc=$?
    if [[ "$rc" -ne 1 ]]; then
      printf 'failed to read git core.hooksPath for %s\n' "$repo_path" >&2
      return "$rc"
    fi
  fi

  if [[ "$has_hooks_path" == "1" ]]; then
    if [[ -z "$hooks_path" || "$hooks_path" == "/dev/null" ]]; then
      printf 'git core.hooksPath disables hooks for %s\n' "$repo_path" >&2
      return 1
    fi
    if [[ "$hooks_path" = /* ]]; then
      hooks_dir="$(physical_path "$hooks_path")"
    else
      hooks_dir="$(physical_path "$project_root/$hooks_path")"
    fi
    project_root="$(physical_path "$project_root")"
    common_dir="$(physical_path "$common_dir")"
    if ! path_is_child "$hooks_dir" "$project_root" && ! path_is_child "$hooks_dir" "$common_dir"; then
      printf 'git core.hooksPath points outside the project boundary for %s: %s\n' "$repo_path" "$hooks_dir" >&2
      return 1
    fi
  else
    hooks_dir="$common_dir/hooks"
  fi

  printf '%s\n' "$hooks_dir"
}

for repo_path in "${hook_repos[@]}"; do
  repo_path="$(release_abs_path "$repo_path")"
  hooks_dir="$(resolve_repo_hooks_dir "$repo_path")"
  if [[ ! -d "$hooks_dir" ]]; then
    printf 'repo hooks directory not found: %s\n' "$hooks_dir" >&2
    exit 1
  fi
  for hook_name in pre-commit pre-push; do
    hook_path="$hooks_dir/$hook_name"
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
