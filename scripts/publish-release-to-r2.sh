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
  HASP_R2_PROMOTE_LATEST also refresh latest/ after immutable publish
EOF
}

print_aws() {
  printf 'aws'
  for arg in "$@"; do
    printf ' %q' "$arg"
  done
  printf '\n'
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
release_dir="$(cd "$release_dir" && pwd -P)"

: "${HASP_R2_BUCKET:?HASP_R2_BUCKET is required}"
: "${HASP_R2_ENDPOINT:?HASP_R2_ENDPOINT is required}"
: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID is required}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY is required}"

prefix="${HASP_R2_PREFIX:-hasp/releases}"
prefix="${prefix#/}"
prefix="${prefix%/}"
version_target="s3://${HASP_R2_BUCKET}/${prefix}/${release_tag}/"
version_prefix="${prefix}/${release_tag}/"

if [[ "$dry_run" == "1" ]]; then
  print_aws --endpoint-url "$HASP_R2_ENDPOINT" s3api list-objects-v2 --bucket "$HASP_R2_BUCKET" --prefix "$version_prefix" --max-items 1 --query 'Contents[0].Key' --output text
  (
    cd "$release_dir"
    while IFS= read -r -d '' file; do
      rel="${file#./}"
      print_aws --endpoint-url "$HASP_R2_ENDPOINT" s3api put-object --bucket "$HASP_R2_BUCKET" --key "${version_prefix}${rel}" --body "$release_dir/$rel" --if-none-match '*'
    done < <(find . -type f -print0)
  )
else
  existing="$(
    aws --endpoint-url "$HASP_R2_ENDPOINT" s3api list-objects-v2 \
      --bucket "$HASP_R2_BUCKET" \
      --prefix "$version_prefix" \
      --max-items 1 \
      --query 'Contents[0].Key' \
      --output text
  )"
  if [[ -n "$existing" && "$existing" != "None" && "$existing" != "null" ]]; then
    echo "release prefix already contains objects, refusing to mutate immutable version path: $version_target" >&2
    exit 1
  fi
  (
    cd "$release_dir"
    while IFS= read -r -d '' file; do
      rel="${file#./}"
      aws --endpoint-url "$HASP_R2_ENDPOINT" s3api put-object \
        --bucket "$HASP_R2_BUCKET" \
        --key "${version_prefix}${rel}" \
        --body "$release_dir/$rel" \
        --if-none-match '*' >/dev/null
    done < <(find . -type f -print0)
  )
fi

if [[ "${HASP_R2_PUBLISH_LATEST:-0}" == "1" ]]; then
  echo "HASP_R2_PUBLISH_LATEST is deprecated; use HASP_R2_PROMOTE_LATEST after Worker deployment" >&2
  exit 2
fi

if [[ "${HASP_R2_PROMOTE_LATEST:-0}" == "1" ]]; then
  latest_target="s3://${HASP_R2_BUCKET}/${prefix}/latest/"
  latest_args=(--endpoint-url "$HASP_R2_ENDPOINT" s3 sync "$release_dir/" "$latest_target" --delete)
  if [[ "$dry_run" == "1" ]]; then
    print_aws "${latest_args[@]}"
  else
    aws "${latest_args[@]}"
  fi
fi

echo "published release mirror to $version_target"
