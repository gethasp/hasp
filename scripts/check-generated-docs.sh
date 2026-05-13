#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

expected="public/docs/cli-reference.md"
if [[ ! -f "$expected" && -f "docs/cli-reference.md" ]]; then
  expected="docs/cli-reference.md"
fi
if [[ ! -f "$expected" ]]; then
  printf 'missing generated CLI reference: %s\n' "$expected" >&2
  exit 1
fi

HASP_TEAM_ID="${HASP_TEAM_ID:-TEAMID1234}" bash ./scripts/build.sh >/dev/null

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

generated="$tmp_dir/cli-reference.md"
./bin/hasp docs markdown --out "$generated"

normalize_cli_reference() {
  sed -E 's/^Build: ([^[:space:]]+) \([^)]*\)$/Build: \1 (normalized)/'
}

normalize_cli_reference <"$expected" >"$tmp_dir/expected.normalized.md"
normalize_cli_reference <"$generated" >"$tmp_dir/generated.normalized.md"

if ! diff -u "$tmp_dir/expected.normalized.md" "$tmp_dir/generated.normalized.md"; then
  cat >&2 <<EOF

CLI reference docs are stale.
Regenerate it with:

  ./bin/hasp docs markdown --out $expected

EOF
  exit 1
fi

printf 'generated CLI reference is current\n'
