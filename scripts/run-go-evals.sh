#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

status=0
for dir in ./apps/server ./packages/*; do
  [[ -d "$dir" ]] || continue
  if [[ -d "$dir/internal/evals" ]]; then
    echo "Running evals in $dir"
    if ! (cd "$dir" && go test -tags=integration,hasp_test_fastkdf ./internal/evals); then
      status=1
    fi
  fi
done

exit "$status"
