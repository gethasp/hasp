#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root/apps/server"

profile="$(mktemp)"
fallback_binary="$(mktemp)"
cleanup() {
  rm -f "$profile" "$fallback_binary"
}
trap cleanup EXIT

go test -tags=hasp_test_fastkdf ./internal/audit -coverprofile="$profile"
go tool cover -func="$profile"

fallback_target="${HASP_AUDIT_FALLBACK_TARGET:-freebsd/amd64}"
fallback_goos="${fallback_target%%/*}"
fallback_goarch="${fallback_target#*/}"
if [[ -z "$fallback_goos" || -z "$fallback_goarch" || "$fallback_goos" == "$fallback_goarch" ]]; then
  echo "invalid HASP_AUDIT_FALLBACK_TARGET: $fallback_target" >&2
  exit 2
fi
GOOS="$fallback_goos" GOARCH="$fallback_goarch" CGO_ENABLED=0 \
  go test -tags=hasp_test_fastkdf -run '^$' -c -o "$fallback_binary" ./internal/audit
printf 'audit fallback build guard passed for %s/%s\n' "$fallback_goos" "$fallback_goarch"

target="${HASP_COVERAGE_TARGET:-100}"
total="$(go tool cover -func="$profile" | awk '/^total:/{print $3}' | tr -d '%')"
awk -v total="$total" -v target="$target" 'BEGIN { exit !(total + 0 >= target + 0) }' || {
  echo "audit platform coverage ${total}% is below target ${target}%" >&2
  exit 1
}
