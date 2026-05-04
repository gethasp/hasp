#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bench_flags=(-run '^$' -bench . -benchmem)
if [[ "${1:-}" == "--smoke" ]]; then
  bench_flags+=(-benchtime=1x -count=1)
fi

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
  echo "No Go modules found; skipping benchmarks."
  exit 0
fi

for mod in "${modules[@]}"; do
  dir="$(dirname "$mod")"
  echo "Benchmarking $dir"
  (cd "$dir" && go test -tags=hasp_test_fastkdf "${bench_flags[@]}" ./...)
done
