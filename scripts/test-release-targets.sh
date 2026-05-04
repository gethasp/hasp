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

generated="$(mktemp)"
cleanup() {
  /bin/rm -f "$generated"
}
trap cleanup EXIT

python3 "$ROOT/scripts/release_targets.py" worker-js >"$generated"
diff -u "$generated" "$ROOT/apps/web/downloads/src/release-targets.generated.js"
if [[ -f "$ROOT/public/apps/web/downloads/src/release-targets.generated.js" ]]; then
  diff -u "$generated" "$ROOT/public/apps/web/downloads/src/release-targets.generated.js"
fi

while read -r goos goarch _runner; do
  python3 "$ROOT/scripts/release_targets.py" has-target "$goos/$goarch"
done < <(python3 "$ROOT/scripts/release_targets.py" shell)
if python3 "$ROOT/scripts/release_targets.py" has-target windows/amd64; then
  printf 'unexpectedly accepted unsupported release target\n' >&2
  exit 1
fi

grep -Fq 'release_targets.py shell' "$ROOT/scripts/release-smoke.sh"
grep -Fq 'release-targets.json' "$ROOT/scripts/render-homebrew-formula.sh"
grep -Fq 'release-targets.json' "$ROOT/scripts/test-package-public-release.sh"

printf 'release target checks passed\n'
