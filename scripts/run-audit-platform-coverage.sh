#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root/apps/server"

profile="$(mktemp)"
cleanup() {
  rm -f "$profile"
}
trap cleanup EXIT

go test -tags=hasp_test_fastkdf ./internal/audit -coverprofile="$profile"
go tool cover -func="$profile"

target="${HASP_COVERAGE_TARGET:-100}"
total="$(go tool cover -func="$profile" | awk '/^total:/{print $3}' | tr -d '%')"
awk -v total="$total" -v target="$target" 'BEGIN { exit !(total + 0 >= target + 0) }' || {
  echo "audit platform coverage ${total}% is below target ${target}%" >&2
  exit 1
}
