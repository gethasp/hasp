#!/usr/bin/env bash
set -euo pipefail

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${HASP_TEST_ROOT:-}" ]]; then
  ROOT="$(cd "$HASP_TEST_ROOT" && pwd)"
elif ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  :
else
  ROOT="$script_root"
fi
cd "$ROOT"

docs_versioning_paths=()
while IFS= read -r docs_versioning_path; do
  [[ -n "$docs_versioning_path" && "$docs_versioning_path" != \#* ]] || continue
  docs_versioning_paths+=("$docs_versioning_path")
done < "$ROOT/scripts/docs-versioning-inputs.txt"
docs_versioning_git_paths=()
for docs_versioning_path in "${docs_versioning_paths[@]}"; do
  docs_versioning_path="${docs_versioning_path#./}"
  docs_versioning_git_paths+=("$docs_versioning_path")
  if [[ "$docs_versioning_path" == public/* ]]; then
    docs_versioning_git_paths+=("${docs_versioning_path#public/}")
  fi
done
mode="${1:-run}"

docs_versioning_paths_match() {
  local changed_path="${1#./}"
  local watched_path="${2#./}"
  changed_path="${changed_path%/}"
  watched_path="${watched_path%/}"
  [[ -n "$changed_path" && -n "$watched_path" ]] || return 1
  if [[ "$changed_path" == "$watched_path" || "$changed_path" == "$watched_path"/* ]]; then
    return 0
  fi
  if [[ "public/$changed_path" == "$watched_path" || "public/$changed_path" == "$watched_path"/* ]]; then
    return 0
  fi
  if [[ "$changed_path" == "public/$watched_path" || "$changed_path" == "public/$watched_path"/* ]]; then
    return 0
  fi
  return 1
}

docs_versioning_path_is_watched() {
  local changed_path="${1#./}"
  local watched_path=""
  for watched_path in "${docs_versioning_paths[@]}"; do
    if docs_versioning_paths_match "$changed_path" "$watched_path"; then
      return 0
    fi
  done
  return 1
}

docs_versioning_changed_paths_need() {
  local changed_paths_file="$1"
  local changed_path=""
  while IFS= read -r changed_path; do
    [[ -n "$changed_path" && "$changed_path" != \#* ]] || continue
    if docs_versioning_path_is_watched "$changed_path"; then
      return 0
    fi
  done < "$changed_paths_file"
  return 1
}

docs_versioning_needed() {
  if [[ "${HASP_DOCS_VERSIONING_FORCE:-0}" == "1" ]]; then
    return 0
  fi
  if [[ "${HASP_DOCS_VERSIONING_SKIP:-0}" == "1" ]]; then
    return 1
  fi
  if [[ -n "${HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE:-}" ]]; then
    docs_versioning_changed_paths_need "$HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE"
    return $?
  fi
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    return 0
  fi

  if git status --short -- "${docs_versioning_git_paths[@]}" | grep -q .; then
    return 0
  fi

  local base="${HASP_DOCS_VERSIONING_BASE:-}"
  if [[ -z "$base" ]] && git rev-parse --verify origin/main >/dev/null 2>&1; then
    base="$(git merge-base HEAD origin/main)"
  fi
  if [[ -z "$base" ]] && git rev-parse --verify HEAD~1 >/dev/null 2>&1; then
    base="$(git rev-parse HEAD~1)"
  fi
  if [[ -z "$base" ]] || ! git cat-file -e "$base^{commit}" 2>/dev/null; then
    return 0
  fi

  ! git diff --quiet "$base"...HEAD -- "${docs_versioning_git_paths[@]}"
}

if [[ "$mode" == "--check" ]]; then
  if docs_versioning_needed; then
    printf 'true\n'
  else
    printf 'false\n'
  fi
  exit 0
fi

if docs_versioning_needed; then
  if [[ "${HASP_DOCS_VERSIONING_PREBUILT:-0}" != "1" ]]; then
    pnpm -C apps/web build
  fi
  pnpm -C apps/web test:docs-versioning
else
  printf 'docs-versioning skipped: docs/web snapshot inputs unchanged\n'
fi
