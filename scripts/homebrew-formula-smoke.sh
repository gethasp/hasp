#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: homebrew-formula-smoke.sh <formula-path>

Install and test a generated HASP Homebrew formula through a temporary local
tap. Modern Homebrew rejects loose formula paths in CI; the tap path exercises
the same installation surface users receive after publication.
EOF
}

if [[ $# -ne 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage >&2
  exit 2
fi

formula_path="$1"
if [[ ! -f "$formula_path" ]]; then
  printf 'formula does not exist: %s\n' "$formula_path" >&2
  exit 1
fi
if ! command -v brew >/dev/null 2>&1; then
  printf 'brew is required for Homebrew formula smoke\n' >&2
  exit 1
fi
if [[ "${CI:-}" != "true" ]] && brew list --formula --versions hasp >/dev/null 2>&1; then
  printf 'skipping Homebrew formula install smoke because formula "hasp" is already installed locally\n' >&2
  printf 'CI runners still execute the tap-qualified install path.\n' >&2
  exit 0
fi

tap_repo="$(mktemp -d)"
tap_name="gethasp/hasp-release-smoke-$$-${RANDOM:-0}"
installed=0
tapped=0

cleanup() {
  if [[ "$installed" == "1" ]]; then
    HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_FROM_API=1 brew uninstall --formula "$tap_name/hasp" >/dev/null 2>&1 || true
  fi
  if [[ "$tapped" == "1" ]]; then
    HOMEBREW_NO_AUTO_UPDATE=1 brew untap "$tap_name" >/dev/null 2>&1 || true
  fi
  /bin/rm -rf "$tap_repo"
}
trap cleanup EXIT

/bin/mkdir -p "$tap_repo/Formula"
/bin/cp -f "$formula_path" "$tap_repo/Formula/hasp.rb"
git -C "$tap_repo" init -b main >/dev/null
git -C "$tap_repo" config user.name "HASP Release Smoke"
git -C "$tap_repo" config user.email "hasp@example.invalid"
git -C "$tap_repo" add Formula/hasp.rb
git -C "$tap_repo" -c commit.gpgsign=false commit -m "Add HASP formula smoke fixture" >/dev/null

HOMEBREW_NO_AUTO_UPDATE=1 brew tap "$tap_name" "$tap_repo" >/dev/null
tapped=1
HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_FROM_API=1 brew install --formula "$tap_name/hasp" >/dev/null
installed=1
HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_FROM_API=1 brew test "$tap_name/hasp" >/dev/null
"$(brew --prefix "$tap_name/hasp")/bin/hasp" version >/dev/null
