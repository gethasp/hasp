#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
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
  echo "No Go modules found; skipping coverage."
  exit 0
fi

merge_profiles_max() {
  local output="$1"
  shift

  awk '
    FNR == 1 {
      if (NR == 1) {
        mode = $0
      }
      next
    }
    {
      key = $1 FS $2
      if (!(key in max) || $3 > max[key]) {
        max[key] = $3
      }
    }
    END {
      print mode
      for (key in max) {
        print key, max[key]
      }
    }
  ' "$@" >"$output"
}

for mod in "${modules[@]}"; do
  dir="$(dirname "$mod")"
  echo "Coverage for $dir"
  eval_profile="$(mktemp)"
  combined_profile="$(mktemp)"
  profiles=()
  (
    cd "$dir"
    while IFS= read -r pkg; do
      [[ -n "$pkg" ]] || continue
      if [[ "$pkg" == *"/internal/evals" ]]; then
        continue
      fi
      pkg_profile="$(mktemp)"
      go test "$pkg" -coverprofile="$pkg_profile" >/dev/null
      profiles+=("$pkg_profile")
    done < <(go list ./...)

    if [[ -d "./internal/evals" ]]; then
      go test -tags=integration -coverpkg=./... ./internal/evals -coverprofile="$eval_profile" >/dev/null
      profiles+=("$eval_profile")
    fi

    merge_profiles_max "$combined_profile" "${profiles[@]}"
    go tool cover -func="$combined_profile" | tail -n 20
    if [[ -n "${HASP_COVERAGE_TARGET:-}" ]]; then
      total="$(go tool cover -func="$combined_profile" | awk '/^total:/{print $3}' | tr -d '%')"
      awk -v total="$total" -v target="$HASP_COVERAGE_TARGET" 'BEGIN { exit !(total + 0 >= target + 0) }' || {
        echo "coverage ${total}% is below target ${HASP_COVERAGE_TARGET}%" >&2
        exit 1
      }
    fi

    for profile in "${profiles[@]}"; do
      rm -f "$profile"
    done
  )
  rm -f "$eval_profile" "$combined_profile"
done
