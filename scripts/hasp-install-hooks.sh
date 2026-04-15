#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
hasp_root="$(cd "$script_dir/.." && pwd)"
project_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
hooks_dir="$project_root/.git/hooks"
mkdir -p "$hooks_dir"

install_hook() {
  local source_file="$1"
  local target_name="$2"
  cat >"$hooks_dir/$target_name" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export HASP_ROOT_OVERRIDE="$hasp_root"
source "$source_file"
EOF
  chmod +x "$hooks_dir/$target_name"
}

install_hook "$hasp_root/scripts/hasp-pre-commit.sh" pre-commit
install_hook "$hasp_root/scripts/hasp-pre-push.sh" pre-push

echo "Installed HASP git hooks in $hooks_dir"
