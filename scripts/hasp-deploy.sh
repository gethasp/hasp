#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/hasp-common.sh
source "$script_dir/hasp-common.sh"

project_root="${1:-}"
shift || true

if [[ -z "$project_root" ]]; then
  echo "usage: $0 <project-root> -- <command> [args...]" >&2
  exit 1
fi

if [[ "${1:-}" == "--" ]]; then
  shift
fi

if [[ "$#" -eq 0 ]]; then
  echo "usage: $0 <project-root> -- <command> [args...]" >&2
  exit 1
fi

if [[ "${HASP_ALLOW_MANAGED_SECRETS:-}" == "1" ]]; then
  run_hasp check-repo --project-root "$project_root" --allow-managed-secrets
else
  run_hasp check-repo --project-root "$project_root"
fi
exec "$@"
