#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: check-release-core-change.sh [release-tag]

Reject a release tag unless the candidate commit contains core CLI/app code
changes since the previous released app tag.

Only core terminal app paths count. Release plumbing, website, docs, macOS app,
and public mirror changes do not qualify a new app release.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(git -C "$script_dir/.." rev-parse --show-toplevel)"
cd "$root"

release_tag="${1:-v$(tr -d '[:space:]' < VERSION)}"
if [[ ! "$release_tag" =~ ^v[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  printf 'release tag must be semver-like vX.Y.Z: %s\n' "$release_tag" >&2
  exit 2
fi

candidate_ref="${HASP_RELEASE_CORE_CANDIDATE_REF:-HEAD}"
candidate_commit="$(git rev-parse --verify "${candidate_ref}^{commit}")"
previous_tag="${HASP_RELEASE_PREVIOUS_TAG:-}"
if [[ -z "$previous_tag" ]]; then
  previous_tag="$(
    git tag --merged "$candidate_commit" --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname |
      awk -v current="$release_tag" '$0 != current { print; exit }'
  )"
fi

if [[ -z "$previous_tag" ]]; then
  printf 'no previous app release tag found; allowing initial core release %s\n' "$release_tag"
  exit 0
fi
previous_commit="$(git rev-parse --verify "${previous_tag}^{commit}")"

core_paths=(
  apps/server
  packages
)

if git diff --quiet "$previous_commit" "$candidate_commit" -- "${core_paths[@]}"; then
  printf 'release %s is blocked: no core CLI/app code changed since %s\n' "$release_tag" "$previous_tag" >&2
  printf 'qualifying paths: %s\n' "${core_paths[*]}" >&2
  printf 'website, docs, workflow, macOS app, public mirror, and release-plumbing changes do not qualify a new app tag\n' >&2
  exit 1
fi

printf 'release %s has core CLI/app changes since %s:\n' "$release_tag" "$previous_tag"
git diff --name-only "$previous_commit" "$candidate_commit" -- "${core_paths[@]}" |
  sed 's/^/  /'
