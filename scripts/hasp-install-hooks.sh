#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
hasp_root="$(cd "$script_dir/.." && pwd)"

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

resolve_hooks_dir() {
  if ! git_hardened -c core.hooksPath=/dev/null -c safe.directory='*' rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf 'not a git working tree; cannot install HASP hooks\n' >&2
    return 1
  fi

  local project_root
  local common_dir
  local hooks_path=""
  local hooks_dir
  local has_hooks_path=0
  project_root="$(git_hardened -c core.hooksPath=/dev/null -c safe.directory='*' rev-parse --show-toplevel)"
  common_dir="$(git_hardened -c core.hooksPath=/dev/null -c safe.directory='*' rev-parse --path-format=absolute --git-common-dir)"
  if hooks_path="$(git_hardened -c safe.directory='*' config --path --get core.hooksPath 2>/dev/null)"; then
    has_hooks_path=1
  else
    local rc=$?
    if [[ "$rc" -ne 1 ]]; then
      printf 'failed to read git core.hooksPath\n' >&2
      return "$rc"
    fi
  fi

  if [[ "$has_hooks_path" == "1" ]]; then
    if [[ -z "$hooks_path" || "$hooks_path" == "/dev/null" ]]; then
      printf 'git core.hooksPath disables hooks; refusing to report HASP hooks installed\n' >&2
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
      printf 'git core.hooksPath points outside the project boundary: %s\n' "$hooks_dir" >&2
      return 1
    fi
  else
    hooks_dir="$common_dir/hooks"
  fi

  printf '%s\n' "$hooks_dir"
}

hooks_dir="$(resolve_hooks_dir)"
mkdir -p "$hooks_dir"

install_hook() {
  local source_file="$1"
  local target_name="$2"
  local target_path="$hooks_dir/$target_name"
  local backup_path="$target_path.pre-hasp"
  if [[ -L "$target_path" || -L "$backup_path" ]]; then
    printf 'refusing to overwrite symlink hook path: %s\n' "$target_path" >&2
    return 1
  fi
  if [[ -f "$target_path" ]] && ! grep -q "HASP-MANAGED-HOOK" "$target_path"; then
    cp -f "$target_path" "$backup_path"
  fi
  cat >"$target_path" <<EOF
#!/usr/bin/env bash
set -euo pipefail
# HASP-MANAGED-HOOK
export HASP_ROOT_OVERRIDE="$hasp_root"
source "$source_file"
if [[ -x "$backup_path" ]]; then
  "$backup_path" "\$@"
fi
EOF
  chmod +x "$target_path"
}

install_hook "$hasp_root/scripts/hasp-pre-commit.sh" pre-commit
install_hook "$hasp_root/scripts/hasp-pre-push.sh" pre-push

echo "Installed HASP git hooks in $hooks_dir"
