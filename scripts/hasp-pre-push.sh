#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/hasp-common.sh
source "$script_dir/hasp-common.sh"

cd "$project_root"
if [[ "${HASP_ALLOW_MANAGED_SECRETS:-}" == "1" ]]; then
  run_hasp check-repo --project-root "$project_root" --allow-managed-secrets
else
  run_hasp check-repo --project-root "$project_root"
fi
