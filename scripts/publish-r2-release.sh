#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${HASP_R2_ENDPOINT:-}" && -n "${HASP_R2_ACCOUNT_ID:-}" ]]; then
  export HASP_R2_ENDPOINT="https://${HASP_R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
fi
exec bash "$script_dir/publish-release-to-r2.sh" "$@"
