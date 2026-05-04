#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${HASP_TEST_ROOT:-}" ]]; then
  repo_root="$(cd "$HASP_TEST_ROOT" && pwd)"
else
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
cd "$repo_root"

modules=()
while IFS= read -r mod; do
  [[ -n "$mod" ]] || continue
  modules+=("$mod")
done < <(
  {
    find ./apps/server -name go.mod -not -path '*/vendor/*' -print 2>/dev/null || true
    find ./packages -name go.mod -not -path '*/vendor/*' -print 2>/dev/null || true
  } | sort -u
)

if [[ "${#modules[@]}" -eq 0 ]]; then
  echo "No Go modules found; skipping go mod tidy check."
  exit 0
fi

status=0
for mod in "${modules[@]}"; do
  dir="$(dirname "$mod")"
  echo "Checking tidy state in $dir"
  pushd "$dir" >/dev/null
  cp -f go.mod go.mod.bak
  had_go_sum=0
  if [[ -f go.sum ]]; then
    had_go_sum=1
    cp -f go.sum go.sum.bak
  fi
  go mod tidy
  if ! cmp -s go.mod.bak go.mod; then
    echo "go.mod is not tidy in $dir" >&2
    status=1
  fi
  if [[ "$had_go_sum" -eq 1 ]]; then
    if ! cmp -s go.sum.bak go.sum; then
      echo "go.sum is not tidy in $dir" >&2
      status=1
    fi
  elif [[ -f go.sum ]]; then
    echo "go.sum is not tidy in $dir" >&2
    status=1
  fi
  mv -f go.mod.bak go.mod
  if [[ "$had_go_sum" -eq 1 ]]; then
    mv -f go.sum.bak go.sum
  else
    rm -f go.sum
  fi
  popd >/dev/null
done

exit "$status"
