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

tmp_files=()
cleanup_tmp_files() {
  if [[ "${#tmp_files[@]}" -gt 0 ]]; then
    /bin/rm -f "${tmp_files[@]}"
  fi
}
trap cleanup_tmp_files EXIT

make_tmp_file() {
  local tmp
  tmp="$(mktemp)"
  tmp_files+=("$tmp")
  printf '%s\n' "$tmp"
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

release_file_list() {
  (
    cd "$release_dir"
    find . -type f -print | sed 's#^\./##' | LC_ALL=C sort
  )
}

put_release_objects() {
  local target_prefix="$1"
  local if_none_match="${2:-0}"
  local rel
  while IFS= read -r rel; do
    if [[ "$dry_run" == "1" ]]; then
      if [[ "$if_none_match" == "1" ]]; then
        print_aws --endpoint-url "$HASP_R2_ENDPOINT" s3api put-object --bucket "$HASP_R2_BUCKET" --key "${target_prefix}${rel}" --body "$release_dir/$rel" --if-none-match '*'
      else
        print_aws --endpoint-url "$HASP_R2_ENDPOINT" s3api put-object --bucket "$HASP_R2_BUCKET" --key "${target_prefix}${rel}" --body "$release_dir/$rel"
      fi
    elif [[ "$if_none_match" == "1" ]]; then
      aws --endpoint-url "$HASP_R2_ENDPOINT" s3api put-object \
        --bucket "$HASP_R2_BUCKET" \
        --key "${target_prefix}${rel}" \
        --body "$release_dir/$rel" \
        --if-none-match '*' >/dev/null
    else
      aws --endpoint-url "$HASP_R2_ENDPOINT" s3api put-object \
        --bucket "$HASP_R2_BUCKET" \
        --key "${target_prefix}${rel}" \
        --body "$release_dir/$rel" >/dev/null
    fi
  done
}

promote_latest_release() {
  local latest_prefix="${prefix}/latest/"
  local latest_target="s3://${HASP_R2_BUCKET}/${latest_prefix}"
  local expected_files
  local existing_keys
  local key
  local rel

  echo "promoting latest release mirror to $latest_target"

  expected_files="$(make_tmp_file)"
  release_file_list >"$expected_files"

  if [[ "$dry_run" == "1" ]]; then
    print_aws --endpoint-url "$HASP_R2_ENDPOINT" s3api list-objects-v2 --bucket "$HASP_R2_BUCKET" --prefix "$latest_prefix" --query 'Contents[].Key' --output text
    put_release_objects "$latest_prefix" 0 <"$expected_files"
    echo "dry run: stale latest objects not present in $release_dir would be deleted"
    return 0
  fi

  put_release_objects "$latest_prefix" 0 <"$expected_files"

  existing_keys="$(make_tmp_file)"
  aws --endpoint-url "$HASP_R2_ENDPOINT" s3api list-objects-v2 \
    --bucket "$HASP_R2_BUCKET" \
    --prefix "$latest_prefix" \
    --query 'Contents[].Key' \
    --output text |
    tr '\t' '\n' |
    sed '/^$/d' |
    LC_ALL=C sort >"$existing_keys"

  while IFS= read -r key; do
    rel="${key#"$latest_prefix"}"
    if ! grep -Fxq "$rel" "$expected_files"; then
      aws --endpoint-url "$HASP_R2_ENDPOINT" s3api delete-object \
        --bucket "$HASP_R2_BUCKET" \
        --key "$key" >/dev/null
    fi
  done <"$existing_keys"
}

if [[ "$dry_run" == "1" ]]; then
  print_aws --endpoint-url "$HASP_R2_ENDPOINT" s3api list-objects-v2 --bucket "$HASP_R2_BUCKET" --prefix "$version_prefix" --max-items 1 --query 'Contents[0].Key' --output text
  release_file_list | put_release_objects "$version_prefix" 1
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
    if [[ "${HASP_R2_PROMOTE_LATEST:-0}" != "1" ]]; then
      echo "release prefix already contains objects, refusing to mutate immutable version path: $version_target" >&2
      exit 1
    fi
    echo "release prefix already exists; promoting latest without mutating immutable version path: $version_target"
  else
    release_file_list | put_release_objects "$version_prefix" 1
  fi
fi

if [[ "${HASP_R2_PUBLISH_LATEST:-0}" == "1" ]]; then
  echo "HASP_R2_PUBLISH_LATEST is deprecated; use HASP_R2_PROMOTE_LATEST after Worker deployment" >&2
  exit 2
fi

if [[ "${HASP_R2_PROMOTE_LATEST:-0}" == "1" ]]; then
  promote_latest_release
fi

echo "published release mirror to $version_target"
