#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: check-release-readiness.sh [options] [release-tag]

Run local pre-tag checks that predict whether a HASP public release is ready to
cut. This command does not create, move, push, or publish tags.

Options:
  --full               Run the heavy release gate instead of the fast readiness gate
  --skip-docs-dry-run  Skip the generated docs snapshot simulation
  -h, --help           Show this help
EOF
}

full=0
skip_docs_dry_run=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --full)
      full=1
      shift
      ;;
    --skip-docs-dry-run)
      skip_docs_dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      printf 'unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
    *)
      break
      ;;
  esac
done
if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi

root="$(git rev-parse --show-toplevel)"
cd "$root"

version="$(tr -d '[:space:]' < VERSION)"
release_tag="${1:-v$version}"
public_remote="${HASP_PUBLIC_RELEASE_REMOTE:-git@github.com:gethasp/hasp.git}"
source_remote="${HASP_SOURCE_REMOTE:-origin}"

say() {
  printf '== %s ==\n' "$1"
}

fail() {
  printf 'release readiness failed: %s\n' "$1" >&2
  exit 1
}

if [[ "$release_tag" != "v$version" ]]; then
  fail "release tag $release_tag does not match VERSION $version"
fi
if [[ ! "$release_tag" =~ ^v[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  fail "release tag must be semver-like vX.Y.Z: $release_tag"
fi

say "Worktree"
tracked_dirty="$(git status --porcelain --untracked-files=no)"
if [[ -n "$tracked_dirty" ]]; then
  printf '%s\n' "$tracked_dirty" >&2
  fail "tracked worktree changes must be committed before release readiness can be trusted"
fi
printf '[ok] tracked worktree is clean\n'

say "Release metadata"
if ! grep -Fq "## [$release_tag]" public/CHANGELOG.md; then
  fail "public/CHANGELOG.md is missing section ## [$release_tag]"
fi
printf '[ok] VERSION and changelog match %s\n' "$release_tag"

say "Tag availability"
local_tag_commit="$(
  git show-ref --tags --dereference "$release_tag" 2>/dev/null |
    awk '$2 ~ /\^\{\}$/ { peeled = $1 } $2 !~ /\^\{\}$/ { direct = $1 } END { print peeled ? peeled : direct }'
)" || true
if [[ -n "$local_tag_commit" ]]; then
  head_commit="$(git rev-parse HEAD)"
  if [[ "$local_tag_commit" != "$head_commit" ]]; then
    fail "local tag $release_tag points at $local_tag_commit, not HEAD $head_commit"
  fi
  printf '[warn] local tag %s already exists at HEAD; cut-public-release can publish it, but pre-tag readiness is no longer purely pre-tag\n' "$release_tag"
else
  printf '[ok] local tag %s is not created yet\n' "$release_tag"
fi

check_remote_tag_absent() {
  local remote="$1"
  local label="$2"
  [[ -n "$remote" ]] || return 0
  local remote_tag
  remote_tag="$(
    git ls-remote --tags "$remote" "refs/tags/$release_tag" "refs/tags/$release_tag^{}" 2>/dev/null |
      awk '$2 ~ /\^\{\}$/ { peeled = $1 } $2 !~ /\^\{\}$/ { direct = $1 } END { print peeled ? peeled : direct }'
  )" || true
  if [[ -n "$remote_tag" ]]; then
    fail "$label already has tag $release_tag at $remote_tag"
  fi
  printf '[ok] %s has no %s tag yet\n' "$label" "$release_tag"
}
check_remote_tag_absent "$source_remote" "$source_remote"
check_remote_tag_absent "$public_remote" "$public_remote"

say "Core app delta"
HASP_RELEASE_CORE_CANDIDATE_REF=HEAD bash "$root/scripts/check-release-core-change.sh" "$release_tag"

docs_app_rel="apps/${HASP_PRIVATE_DOCS_APP_NAME:-web}"
docs_app_dir="$root/$docs_app_rel"
if [[ "$skip_docs_dry_run" == "0" && -d "$docs_app_dir" ]]; then
  say "Docs generation dry-run"
  tmp_dir="$(mktemp -d)"
  cleanup() {
    /bin/rm -rf "$tmp_dir"
  }
  trap cleanup EXIT

  git clone --quiet --no-hardlinks "$root" "$tmp_dir/source"
  (
    cd "$tmp_dir/source"
    git tag -f "$release_tag" -m "Release $release_tag" HEAD
    HASP_TEAM_ID="${HASP_TEAM_ID:-TEAMID1234}" bash scripts/build.sh >/dev/null
    bin/hasp docs markdown --out public/docs/cli-reference.md
    HASP_DOCS_SNAPSHOT_SKIP_CHECK=1 pnpm -C "$docs_app_rel" docs:snapshot -- "$release_tag" --force >/dev/null

    allowed_dirty="$(git status --porcelain -- public/docs/cli-reference.md public/docs-metadata.json public/docs-versions)"
    generated_dirty="$(git status --porcelain --untracked-files=no)"
    disallowed_dirty="$(
      printf '%s\n' "$generated_dirty" |
        awk '$2 !~ /^public\/docs\/cli-reference[.]md$/ && $2 !~ /^public\/docs-metadata[.]json$/ && $2 !~ /^public\/docs-versions\// { print }'
    )"
    if [[ -n "$disallowed_dirty" ]]; then
      printf '%s\n' "$disallowed_dirty" >&2
      exit 10
    fi
    if [[ -n "$allowed_dirty" ]]; then
      printf '[warn] release docs generation will create a docs commit:\n'
      printf '%s\n' "$allowed_dirty"
    else
      printf '[ok] generated release docs are already current\n'
    fi
  ) || {
    code=$?
    if [[ "$code" == "10" ]]; then
      fail "docs dry-run changed files outside the release docs allowlist"
    fi
    exit "$code"
  }
  trap - EXIT
  cleanup
else
  printf '[skip] docs generation dry-run skipped\n'
fi

say "Local gates"
if [[ "$full" == "1" ]]; then
  HASP_COVERAGE_TARGET="${HASP_COVERAGE_TARGET:-100}" HASP_DOCS_VERSIONING_SKIP=1 make release-gate
else
  HASP_DOCS_VERSIONING_SKIP=1 make release-preflight
fi

printf 'release readiness passed for %s\n' "$release_tag"
