#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

modules=()
while IFS= read -r mod; do
  [[ -n "$mod" ]] || continue
  modules+=("$mod")
done < <(
  {
    find ./apps/server -name go.mod -not -path '*/vendor/*' -print 2>/dev/null || true
    find ./packages -name go.mod -not -path '*/vendor/*' -print 2>/dev/null || true
    find ./tools -name go.mod -not -path '*/vendor/*' -print 2>/dev/null || true
  } | sort -u
)

if [[ "${#modules[@]}" -eq 0 ]]; then
  echo "No Go modules found; skipping coverage."
  exit 0
fi

if [[ -n "${HASP_COVERAGE_TARGET:-}" ]]; then
  awk -v target="$HASP_COVERAGE_TARGET" 'BEGIN {
    exit !(target ~ /^[0-9]+([.][0-9]+)?$/ && target + 0 <= 100)
  }' || { echo "HASP_COVERAGE_TARGET must be between 0 and 100" >&2; exit 2; }
fi

output_dir="${HASP_COVERAGE_OUTPUT_DIR:-}"
if [[ -n "$output_dir" ]]; then
  mkdir -p "$output_dir"
  output_dir="$(cd "$output_dir" && pwd)"
fi
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

merge_profiles_max() {
  local output="$1"
  shift
  awk '
    FNR == 1 { if (NR == 1) mode = $0; next }
    {
      key = $1 FS $2
      if (!(key in max) || $3 > max[key]) max[key] = $3
    }
    END {
      print mode
      for (key in max) print key, max[key]
    }
  ' "$@" >"$output"
}

for mod in "${modules[@]}"; do
  dir="$(dirname "$mod")"
  echo "Coverage for $dir"
  (
    cd "$dir"
    package_list="$(go list ./...)"
    coverage_packages=()
    while IFS= read -r pkg; do
      [[ -n "$pkg" ]] || continue
      if [[ "$pkg" == *"/internal/evals" || "$pkg" == *"/internal/testutil" ]]; then
        continue
      fi
      coverage_packages+=("$pkg")
    done <<<"$package_list"
    if [[ "${#coverage_packages[@]}" -eq 0 ]]; then
      echo "No production packages found in $dir" >&2
      exit 1
    fi
    coverpkg="$(IFS=,; printf '%s' "${coverage_packages[*]}")"
    profiles=("$scratch/unit.out")
    # Instrument every production package so tests through callers count too.
    if ! go test -p "${HASP_GO_TEST_PACKAGE_PARALLELISM:-1}" -tags=hasp_test_fastkdf \
      -coverpkg="$coverpkg" -coverprofile="${profiles[0]}" ./... >"$scratch/test.log" 2>&1; then
      echo "coverage run failed for $dir:" >&2
      cat "$scratch/test.log" >&2
      exit 1
    fi
    if [[ -d ./internal/evals ]]; then
      profiles+=("$scratch/evals.out")
      if ! go test -p 1 -tags=integration,hasp_test_fastkdf -coverpkg="$coverpkg" \
        ./internal/evals -coverprofile="$scratch/evals.out" >"$scratch/test.log" 2>&1; then
        echo "coverage run failed for ./internal/evals:" >&2
        cat "$scratch/test.log" >&2
        exit 1
      fi
    fi
    merge_profiles_max "$scratch/combined.out" "${profiles[@]}"
    go tool cover -func="$scratch/combined.out" >"$scratch/functions.txt"
    tail -n 20 "$scratch/functions.txt"
    awk 'NR > 1 { total += $2; if ($3 > 0) covered += $2 }
      END { printf "Covered %.0f/%.0f statements (%.6f%%); %.0f uncovered\n", covered, total, total ? 100 * covered / total : 100, total - covered }
    ' "$scratch/combined.out"
    if [[ -n "$output_dir" ]]; then
      module_output="$output_dir/${dir#./}"
      mkdir -p "$module_output"
      cp "$scratch/combined.out" "$module_output/coverage.out"
      cp "$scratch/functions.txt" "$module_output/functions.txt"
      echo "Coverage profile: $module_output/coverage.out"
    fi
    if [[ -n "${HASP_COVERAGE_TARGET:-}" ]]; then
      # Compare statement counts, not go tool cover's rounded display value.
      awk -v target="$HASP_COVERAGE_TARGET" '
        NR > 1 { total += $2; if ($3 > 0) covered += $2 }
        END { exit !(total == 0 || covered * 100 >= target * total) }
      ' "$scratch/combined.out" || {
        echo "statement coverage is below target ${HASP_COVERAGE_TARGET}%" >&2
        awk '$1 != "total:" && $NF ~ /%$/ && $NF != "100.0%" {print}' "$scratch/functions.txt" >&2
        exit 1
      }
    fi
  )
done
