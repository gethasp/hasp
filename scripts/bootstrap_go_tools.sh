#!/usr/bin/env bash
set -euo pipefail

profile="${1:-verify}"
repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
tools_bin="$repo_root/bin/tools"
mkdir -p "$tools_bin"

export GOBIN="$tools_bin"

install() {
  local module="$1"
  echo "Installing $module"
  go install "$module"
}

case "$profile" in
  verify|ci|lint|all)
    install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4"
    install "honnef.co/go/tools/cmd/staticcheck@2025.1.1"
    install "golang.org/x/vuln/cmd/govulncheck@v1.1.4"
    ;;
  *)
    echo "Unknown profile: $profile" >&2
    exit 1
    ;;
esac
