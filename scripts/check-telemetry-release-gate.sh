#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
  printf 'telemetry release gate: %s\n' "$*" >&2
  exit 1
}

telemetry_doc="public/docs/telemetry.md"
if [[ ! -f "$telemetry_doc" && -f "docs/telemetry.md" ]]; then
  telemetry_doc="docs/telemetry.md"
fi
[[ -f "$telemetry_doc" ]] || fail "missing telemetry docs"

grep -q 'HASP_TELEMETRY_DISABLED' "$telemetry_doc" || fail "telemetry docs must document the env kill switch"
grep -q 'telemetry.gethasp.com/v1/cli/ping' "$telemetry_doc" || fail "telemetry docs must document the first-party endpoint"
grep -q 'HASP_TELEMETRY_ENDPOINT' scripts/build.sh || fail "build script must make the endpoint explicit"
grep -q 'telemetry.gethasp.com/v1/cli/ping' scripts/build.sh || fail "build script must pin the production endpoint"

telemetry_worker_src="apps/${HASP_PRIVATE_TELEMETRY_APP_NAME:-telemetry}/src"
third_party_scan_paths=(apps/server/internal/telemetry apps/server/internal/app/telemetry_command.go)
if [[ -d "$telemetry_worker_src" ]]; then
  third_party_scan_paths+=("$telemetry_worker_src")
fi

if rg -n 'posthog|umami|segment\.com|api-js\.mixpanel|plausible' \
  "${third_party_scan_paths[@]}" \
  >/tmp/hasp-telemetry-third-party.$$ 2>/dev/null; then
  cat /tmp/hasp-telemetry-third-party.$$ >&2
  rm -f /tmp/hasp-telemetry-third-party.$$
  fail "CLI/service telemetry code must not reference direct third-party analytics endpoints"
fi
rm -f /tmp/hasp-telemetry-third-party.$$

for forbidden in '"path"' '"repo"' '"alias"' '"ref"' '"argv"' '"env"' '"stdout"' '"stderr"' '"hostname"' '"username"'; do
  if rg -n -g '!**/*_test.go' "$forbidden" apps/server/internal/telemetry >/tmp/hasp-telemetry-forbidden.$$ 2>/dev/null; then
    cat /tmp/hasp-telemetry-forbidden.$$ >&2
    rm -f /tmp/hasp-telemetry-forbidden.$$
    fail "telemetry payload code contains forbidden key token $forbidden"
  fi
done
rm -f /tmp/hasp-telemetry-forbidden.$$

printf 'telemetry release gate: ok\n'
