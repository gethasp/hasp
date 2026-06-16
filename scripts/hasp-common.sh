#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
hasp_root="${HASP_ROOT_OVERRIDE:-$(cd "$script_dir/.." && pwd)}"
project_root="$(git -c core.hooksPath=/dev/null -c safe.directory='*' rev-parse --show-toplevel 2>/dev/null || pwd)"

resolve_hasp() {
  if [[ -x "$hasp_root/bin/hasp" ]]; then
    printf '%s\n' "$hasp_root/bin/hasp"
    return 0
  fi
  printf 'go run ./apps/server/cmd/hasp\n'
}

run_hasp() {
  if [[ -x "$hasp_root/bin/hasp" ]]; then
    "$hasp_root/bin/hasp" "$@"
    return 0
  fi
  (
    cd "$project_root"
    go run ./apps/server/cmd/hasp "$@"
  )
}
