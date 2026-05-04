#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "$#" -gt 0 ]]; then
  paths=("$@")
elif [[ -d "$ROOT/public/.github/workflows" ]]; then
  paths=("$ROOT/.github/workflows" "$ROOT/public/.github/workflows")
else
  paths=("$ROOT/.github/workflows")
fi

status=0
while IFS= read -r -d '' workflow; do
  line_no=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_no=$((line_no + 1))
    if [[ "$line" =~ ^[[:space:]]*uses:[[:space:]]*([^[:space:]#]+) ]]; then
      action="${BASH_REMATCH[1]}"
      case "$action" in
        ./*|../*|docker://*)
          continue
          ;;
      esac
      if [[ ! "$action" =~ @[0-9a-fA-F]{40}$ ]]; then
        printf '%s:%s: action is not pinned to a full commit SHA: %s\n' "$workflow" "$line_no" "$action" >&2
        status=1
      fi
    fi
  done <"$workflow"
done < <(find "${paths[@]}" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0)

exit "$status"
