#!/usr/bin/env bash
set -euo pipefail

ROOT="${HASP_TEST_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/repo/scripts" "$scratch/repo/apps/server/internal/evals" "$scratch/repo/tools/signer" "$scratch/bin"
cp "$ROOT/scripts/run-go-coverage.sh" "$scratch/repo/scripts/"
touch "$scratch/repo/apps/server/go.mod" "$scratch/repo/tools/signer/go.mod"
cat >"$scratch/bin/go" <<'GO'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  list)
    if [[ "$HASP_TEST_COVERAGE_MODE" == list-error ]]; then exit 1; fi
    printf 'example.test/module\nexample.test/module/child\n'
    ;;
  test)
    profile=""
    for arg in "$@"; do
      case "$arg" in -coverprofile=*) profile="${arg#*=}" ;; esac
    done
    printf '%s\n' "$*" >>"$HASP_TEST_COVERAGE_ARGS"
    missing=0
    if [[ "$HASP_TEST_COVERAGE_MODE" == rounded ]]; then missing=1; fi
    if [[ "$HASP_TEST_COVERAGE_MODE" == merged && "$*" != *-tags=integration,* ]]; then missing=1; fi
    {
      printf 'mode: set\n'
      printf 'example.test/module/main.go:1.1,2.1 1999 1\n'
      printf 'example.test/module/main.go:3.1,4.1 1 %s\n' "$((1 - missing))"
    } >"$profile"
    ;;
  tool)
    # go tool cover rounds 1999/2000 statements to 100.0%.
    printf 'example.test/module/main.go:1:\tmain\t100.0%%\ntotal:\t(statements)\t100.0%%\n'
    ;;
  *) exit 2 ;;
esac
GO
chmod +x "$scratch/bin/go"
export PATH="$scratch/bin:$PATH"
export HASP_TEST_COVERAGE_ARGS="$scratch/args"
export HASP_COVERAGE_OUTPUT_DIR="$scratch/profiles"

if HASP_TEST_COVERAGE_MODE=rounded HASP_COVERAGE_TARGET=100 \
  bash "$scratch/repo/scripts/run-go-coverage.sh" >"$scratch/log" 2>&1; then
  echo 'rounded coverage was accepted as 100%' >&2
  exit 1
fi
grep -Fq 'Covered 1999/2000 statements' "$scratch/log"
test -f "$scratch/profiles/apps/server/coverage.out"

HASP_TEST_COVERAGE_MODE=rounded HASP_COVERAGE_TARGET=99.9 \
  bash "$scratch/repo/scripts/run-go-coverage.sh" >"$scratch/log" 2>&1
test -f "$scratch/profiles/tools/signer/coverage.out"
grep -Fq -- '-coverpkg=example.test/module,example.test/module/child' "$scratch/args"
grep -Fq -- '-p 1 -tags=hasp_test_fastkdf' "$scratch/args"

HASP_TEST_COVERAGE_MODE=merged HASP_COVERAGE_TARGET=100 \
  bash "$scratch/repo/scripts/run-go-coverage.sh" >"$scratch/log" 2>&1 && {
    echo 'uncovered signing tool passed through an unrelated module profile' >&2
    exit 1
  }
grep -Fq 'Covered 2000/2000 statements' "$scratch/log"
grep -Fq 'Covered 1999/2000 statements' "$scratch/log"

HASP_TEST_COVERAGE_MODE=full HASP_COVERAGE_TARGET=100 \
  bash "$scratch/repo/scripts/run-go-coverage.sh" >"$scratch/log" 2>&1
for target in 101 -1 not-a-number; do
  if HASP_TEST_COVERAGE_MODE=full HASP_COVERAGE_TARGET="$target" \
    bash "$scratch/repo/scripts/run-go-coverage.sh" >"$scratch/log" 2>&1; then
    printf 'invalid coverage target accepted: %s\n' "$target" >&2
    exit 1
  fi
done
if HASP_TEST_COVERAGE_MODE=list-error HASP_COVERAGE_TARGET=100 \
  bash "$scratch/repo/scripts/run-go-coverage.sh" >"$scratch/log" 2>&1; then
  echo 'failed package discovery passed coverage' >&2
  exit 1
fi
printf 'Go coverage gate regression tests passed\n'
