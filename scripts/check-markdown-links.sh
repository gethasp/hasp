#!/usr/bin/env bash
set -euo pipefail

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$script_root/VERSION" && -f "$script_root/apps/server/go.mod" && ! -f "$script_root/scripts/export-public-hasp.py" ]]; then
  repo_root="$script_root"
else
  repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi
python3 "$repo_root/scripts/check_markdown_links.py" "$repo_root"
