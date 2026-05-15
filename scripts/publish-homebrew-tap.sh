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
while [[ $# -gt 0 ]]; do
  case "$1" in
    --push)
      push_mode=1
      shift
      ;;
    *)
      break
      ;;
  esac
done

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

formula_path="$(cd "$(dirname "$formula_path")" && pwd)/$(basename "$formula_path")"

(
  cd "$tap_repo"
  if [[ -n "$(git status --porcelain=v1)" ]]; then
    echo "tap repo has uncommitted changes: $tap_repo" >&2
    exit 1
  fi
  if [[ "$push_mode" == "1" ]]; then
    expected_remote="${HASP_HOMEBREW_TAP_REMOTE_URL:-https://github.com/gethasp/homebrew-tap.git}"
    remote_url="$(git remote get-url origin 2>/dev/null || true)"
    if [[ "$remote_url" == "git@github.com:gethasp/homebrew-tap.git" && "$expected_remote" == "https://github.com/gethasp/homebrew-tap.git" ]]; then
      remote_url="$expected_remote"
    fi
    if [[ "${remote_url%.git}.git" != "${expected_remote%.git}.git" ]]; then
      echo "tap repo origin is ${remote_url:-<missing>}, want $expected_remote" >&2
      exit 1
    fi
    branch="$(git symbolic-ref --short HEAD 2>/dev/null || true)"
    if [[ "$branch" != "main" ]]; then
      echo "tap repo must be on main before --push, got ${branch:-detached HEAD}" >&2
      exit 1
    fi
    git fetch --quiet origin main
    git rebase origin/main
  fi

  /bin/mkdir -p Formula
  /bin/cp -f "$formula_path" Formula/hasp.rb

  if [[ -z "$(git config --get user.name || true)" ]]; then
    git config user.name "HASP Bot"
  fi
  if [[ -z "$(git config --get user.email || true)" ]]; then
    git config user.email "bot@gethasp.com"
  fi
  git add Formula/hasp.rb
  if ! git diff --cached --quiet; then
    msg="Update HASP Homebrew tap"
    if [[ -n "$release_tag" ]]; then
      msg="$msg for $release_tag"
    fi
    git -c core.hooksPath=/dev/null -c commit.gpgsign=false commit -m "$msg" >/dev/null
  fi
  if [[ "$push_mode" == "1" ]]; then
    git push origin HEAD:main
  fi
)

echo "updated Homebrew tap checkout at $tap_repo"
