#!/usr/bin/env bash
set -euo pipefail

profile="${1:-}"
if [[ "$profile" == "--profile" ]]; then
  profile="${2:-lint}"
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

tools_bin="$repo_root/bin/tools"
export PATH="$tools_bin:$PATH"

modules=()
while IFS= read -r mod; do
  [[ -n "$mod" ]] || continue
  modules+=("$mod")
done < <(
  {
    find ./apps/server -name go.mod -not -path '*/vendor/*' -print 2>/dev/null || true
    find ./packages -name go.mod -not -path '*/vendor/*' -print 2>/dev/null || true
  } | sort -u
)
if [[ "${#modules[@]}" -eq 0 ]]; then
  echo "No Go modules found; skipping Go analysis."
  exit 0
fi

if ! command -v golangci-lint >/dev/null 2>&1 || ! command -v govulncheck >/dev/null 2>&1 || ! command -v staticcheck >/dev/null 2>&1; then
  echo "Required Go tools missing. Run ./scripts/bootstrap_go_tools.sh verify" >&2
  exit 1
fi

for mod in "${modules[@]}"; do
  dir="$(dirname "$mod")"
  echo "Analyzing $dir with profile $profile"
  case "$profile" in
    lint)
      (cd "$dir" && go vet ./... && golangci-lint run --timeout=10m ./...)
      ;;
    staticcheck)
      (cd "$dir" && staticcheck ./...)
      ;;
    vulncheck)
      (cd "$dir" && govulncheck ./...)
      ;;
    *)
      echo "Unknown analysis profile: $profile" >&2
      exit 1
      ;;
  esac
done
