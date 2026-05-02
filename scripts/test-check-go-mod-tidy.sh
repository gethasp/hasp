#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$script_dir/.." && pwd)"
check_script="$script_dir/check-go-mod-tidy.sh"

/bin/mkdir -p "$ROOT/dist"
tmpdir="$(mktemp -d "$ROOT/dist/test-check-go-mod-tidy.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

repo="$tmpdir/repo"
mkdir -p "$repo/apps/server" "$repo/packages/withsum"
cd "$repo"
git init -q

cat > apps/server/go.mod <<'EOF'
module example.com/nosum

go 1.24.0
EOF

cat > packages/withsum/go.mod <<'EOF'
module example.com/withsum

go 1.24.0

require github.com/google/uuid v1.6.0
EOF

cat > packages/withsum/main.go <<'EOF'
package main

import "github.com/google/uuid"

func main() {
	_ = uuid.NewString()
}
EOF

(cd packages/withsum && go mod tidy >/dev/null 2>&1)

if ! HASP_TEST_ROOT="$repo" bash "$check_script" >"$tmpdir/tidy-ok.log" 2>&1; then
  cat "$tmpdir/tidy-ok.log" >&2
  exit 1
fi

[[ ! -e apps/server/go.mod.bak ]]
[[ ! -e apps/server/go.sum ]]
[[ ! -e apps/server/go.sum.bak ]]
[[ ! -e packages/withsum/go.mod.bak ]]
[[ ! -e packages/withsum/go.sum.bak ]]
[[ -f packages/withsum/go.sum ]]

printf '\nrequire golang.org/x/text v0.14.0\n' >> packages/withsum/go.mod

if HASP_TEST_ROOT="$repo" bash "$check_script" >"$tmpdir/tidy-fail.log" 2>&1; then
  cat "$tmpdir/tidy-fail.log" >&2
  echo "expected tidy check failure for modified go.mod" >&2
  exit 1
fi
grep -q 'go.mod is not tidy' "$tmpdir/tidy-fail.log"

[[ ! -e packages/withsum/go.mod.bak ]]
[[ ! -e packages/withsum/go.sum.bak ]]
grep -q 'golang.org/x/text' packages/withsum/go.mod
