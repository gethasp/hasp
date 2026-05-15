#!/usr/bin/env bash
set -euo pipefail

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${HASP_TEST_ROOT:-}" ]]; then
  ROOT="$(cd "$HASP_TEST_ROOT" && pwd)"
elif [[ -f "$script_root/VERSION" && -f "$script_root/apps/server/go.mod" && ! -f "$script_root/scripts/export-public-hasp.py" ]]; then
  ROOT="$script_root"
elif ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  :
else
  ROOT="$script_root"
fi
export HASP_TEST_ROOT="$ROOT"

tests=(
  scripts/test-check-go-mod-tidy.sh
  scripts/test-public-installer.sh
  scripts/test-public-docs-versioning.sh
  scripts/test-release-metadata-parser.sh
  scripts/test-release-targets.sh
  scripts/check-public-release-contract.py
  scripts/test-package-public-release.sh
)

if [[ -f "$ROOT/scripts/test-check-public-export.sh" ]]; then
  tests+=(scripts/test-check-public-export.sh)
fi

for test_script in "${tests[@]}"; do
  case "$test_script" in
    *.py) python3 "$ROOT/$test_script" ;;
    *) bash "$ROOT/$test_script" ;;
  esac
done
