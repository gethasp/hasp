#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: publish-release-to-r2.sh [--dry-run] <release-dir> <release-tag>

Mirror a prepared public release directory to a Cloudflare R2 bucket.

Required environment:
  HASP_R2_BUCKET
  HASP_R2_ENDPOINT
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY

Optional environment:
  HASP_R2_PREFIX         defaults to hasp/releases
  HASP_R2_PUBLISH_LATEST also refresh latest/
EOF
}

dry_run=0
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=1
  shift
fi

if [[ $# -ne 2 ]]; then
  usage >&2
  exit 1
fi

release_dir="$1"
release_tag="$2"

if [[ ! -d "$release_dir" ]]; then
  echo "release directory not found: $release_dir" >&2
  exit 1
fi

: "${HASP_R2_BUCKET:?HASP_R2_BUCKET is required}"
: "${HASP_R2_ENDPOINT:?HASP_R2_ENDPOINT is required}"
: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID is required}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY is required}"

prefix="${HASP_R2_PREFIX:-hasp/releases}"
version_target="s3://${HASP_R2_BUCKET}/${prefix}/${release_tag}/"

sync_args=(--endpoint-url "$HASP_R2_ENDPOINT" s3 sync "$release_dir/" "$version_target" --delete)
if [[ "$dry_run" == "1" ]]; then
  printf 'aws'
  for arg in "${sync_args[@]}"; do
    printf ' %q' "$arg"
  done
  printf '\n'
else
  aws "${sync_args[@]}"
fi

if [[ "${HASP_R2_PUBLISH_LATEST:-0}" == "1" ]]; then
  latest_target="s3://${HASP_R2_BUCKET}/${prefix}/latest/"
  latest_args=(--endpoint-url "$HASP_R2_ENDPOINT" s3 sync "$release_dir/" "$latest_target" --delete)
  if [[ "$dry_run" == "1" ]]; then
    printf 'aws'
    for arg in "${latest_args[@]}"; do
      printf ' %q' "$arg"
    done
    printf '\n'
  else
    aws "${latest_args[@]}"
  fi
fi

echo "published release mirror to $version_target"
