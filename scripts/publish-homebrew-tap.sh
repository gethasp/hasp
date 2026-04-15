#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  publish-homebrew-tap.sh <formula-path> <tap-repo-dir>
  publish-homebrew-tap.sh --push <formula-path> <tap-repo-dir> <release-tag>
EOF
}

push_mode=0
if [[ "${1:-}" == "--push" ]]; then
  push_mode=1
  shift
fi

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage >&2
  exit 1
fi

formula_path="$1"
tap_repo="$2"
release_tag="${3:-}"

if [[ ! -f "$formula_path" ]]; then
  echo "formula not found: $formula_path" >&2
  exit 1
fi
if [[ ! -d "$tap_repo/.git" ]]; then
  echo "tap repo must be an existing git checkout: $tap_repo" >&2
  exit 1
fi

/bin/mkdir -p "$tap_repo/Formula"
/bin/cp -f "$formula_path" "$tap_repo/Formula/hasp.rb"

(
  cd "$tap_repo"
  if [[ -z "$(git config --get user.name || true)" ]]; then
    git config user.name "HASP Bot"
  fi
  if [[ -z "$(git config --get user.email || true)" ]]; then
    git config user.email "bot@gethasp.com"
  fi
  git add Formula/hasp.rb
  if ! git diff --cached --quiet; then
    msg="Update HASP formula"
    if [[ -n "$release_tag" ]]; then
      msg="$msg for $release_tag"
    fi
    git -c core.hooksPath=/dev/null commit -m "$msg" >/dev/null
  fi
  if [[ "$push_mode" == "1" ]]; then
    git push
  fi
)

echo "updated Homebrew tap checkout at $tap_repo"
