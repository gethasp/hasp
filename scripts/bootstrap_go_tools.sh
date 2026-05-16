#!/usr/bin/env bash
set -euo pipefail

profile="${1:-verify}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tools_bin="$repo_root/bin/tools"
mkdir -p "$tools_bin"

export GOBIN="$tools_bin"

install() {
  local module="$1"
  echo "Installing $module"
  go install "$module"
}

require_tool() {
  local name="$1"
  local install_hint="$2"
  if command -v "$name" >/dev/null 2>&1; then
    return 0
  fi
  printf '%s is required; preinstall it on the runner before invoking this repo script. %s\n' "$name" "$install_hint" >&2
  return 1
}

require_shellcheck() {
  if command -v shellcheck >/dev/null 2>&1; then
    return 0
  fi
  require_tool shellcheck "Ubicloud and macOS CI images should include it; locally install via your system package manager."
}

require_gnupg() {
  if command -v gpg >/dev/null 2>&1; then
    return 0
  fi
  require_tool gpg "Ubicloud and macOS CI images should include it; locally install GnuPG via your system package manager."
}

case "$profile" in
  verify|ci|lint|all)
    install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4"
    install "honnef.co/go/tools/cmd/staticcheck@2025.1.1"
    install "golang.org/x/vuln/cmd/govulncheck@v1.3.0"
    install "github.com/rhysd/actionlint/cmd/actionlint@v1.7.12"
    install "github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.3.8"
    require_shellcheck
    require_gnupg
    ;;
  release-smoke|smoke)
    require_tool go "GitHub Actions release-smoke jobs must run actions/setup-go before this script."
    require_tool python3 "GitHub Actions release-smoke jobs must run on an image with Python 3."
    require_tool git "GitHub Actions release-smoke jobs must run after actions/checkout on an image with git."
    require_gnupg
    ;;
  *)
    echo "Unknown profile: $profile" >&2
    exit 1
    ;;
esac
