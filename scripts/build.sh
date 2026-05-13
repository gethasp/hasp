#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
version="$(< VERSION)"
mode=""
output="${HASP_BUILD_OUTPUT:-}"
target_pkg="./cmd/hasp"
go_build_tags="${HASP_GO_BUILD_TAGS:-}"

usage() {
  cat <<'EOF'
Usage: build.sh [--debug|--min-size] [-o output] [--pkg package]

Build the HASP broker binary.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug|--min-size)
      mode="$1"
      shift
      ;;
    -o|--output)
      if [[ -z "${2:-}" ]]; then
        usage >&2
        exit 2
      fi
      output="$2"
      shift 2
      ;;
    --pkg)
      if [[ -z "${2:-}" ]]; then
        usage >&2
        exit 2
      fi
      target_pkg="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$output" ]]; then
  output="$repo_root/bin/hasp"
fi
case "$output" in
  /*) ;;
  *) output="$repo_root/$output" ;;
esac

# Compute build metadata. Fall back to "unknown" when git is unavailable
# (e.g. building from a source tarball without a .git directory).
commit="${HASP_BUILD_COMMIT:-$(git rev-parse --short=10 HEAD 2>/dev/null || echo unknown)}"
build_date="${HASP_BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

runtime_pkg="github.com/gethasp/hasp/apps/server/internal/runtime"
release_pkg="github.com/gethasp/hasp/apps/server/internal/release"
httpapi_pkg="github.com/gethasp/hasp/apps/server/internal/httpapi"
telemetry_pkg="github.com/gethasp/hasp/apps/server/internal/telemetry"
upgrade_trust_roots="${HASP_UPGRADE_TRUST_ROOTS_HEX:-}"
if [[ -n "$upgrade_trust_roots" && ! "$upgrade_trust_roots" =~ ^[0-9a-fA-F]{64}(,[0-9a-fA-F]{64})*$ ]]; then
  echo "HASP_UPGRADE_TRUST_ROOTS_HEX must be one or more comma-separated 64-hex Ed25519 public keys" >&2
  exit 1
fi
hmac_team_id="${HASP_TEAM_ID:-}"
if [[ -n "$hmac_team_id" && ! "$hmac_team_id" =~ ^[A-Z0-9]{10}$ ]]; then
  echo "HASP_TEAM_ID must be a 10-character Apple Team ID" >&2
  exit 1
fi
target_goos="${GOOS:-$(go env GOOS)}"
if [[ "$target_goos" == "darwin" && -z "$hmac_team_id" ]]; then
  echo "HASP_TEAM_ID must be set for darwin builds so the daemon HTTP HMAC key can be pinned to signed app/daemon requirements" >&2
  exit 1
fi
ldflags_base="\
-X ${runtime_pkg}.Version=${version} \
-X ${runtime_pkg}.Commit=${commit} \
-X ${runtime_pkg}.BuildDate=${build_date}"
if [[ -n "$upgrade_trust_roots" ]]; then
  ldflags_base+=" -X ${release_pkg}.pinnedKeysHex=${upgrade_trust_roots}"
fi
if [[ -n "$hmac_team_id" ]]; then
  ldflags_base+=" -X ${httpapi_pkg}.HMACTeamID=${hmac_team_id}"
fi
telemetry_endpoint="${HASP_TELEMETRY_ENDPOINT:-}"
if [[ -n "$telemetry_endpoint" ]]; then
  case "$telemetry_endpoint" in
    https://telemetry.gethasp.com/v1/cli/ping) ;;
    *)
      echo "HASP_TELEMETRY_ENDPOINT must be https://telemetry.gethasp.com/v1/cli/ping for release builds" >&2
      exit 1
      ;;
  esac
  ldflags_base+=" -X ${telemetry_pkg}.Endpoint=${telemetry_endpoint}"
fi

server_mod="./apps/server/go.mod"

if [[ ! -f "$server_mod" ]]; then
  echo "No apps/server Go module exists yet. Build target is a placeholder until HASP server implementation starts." >&2
  exit 1
fi

case "$target_pkg" in
  ./apps/server/cmd/hasp|apps/server/cmd/hasp|"$repo_root/apps/server/cmd/hasp")
    target_pkg="./cmd/hasp"
    ;;
esac

mkdir -p "$(dirname "$output")"
cd "$repo_root/apps/server"
go_build_args=()
if [[ -n "$go_build_tags" ]]; then
  go_build_args+=("-tags=$go_build_tags")
fi
case "$mode" in
  --debug)
    go build ${go_build_args[@]+"${go_build_args[@]}"} -ldflags="${ldflags_base}" -o "$output" "$target_pkg"
    ;;
  --min-size)
    go build ${go_build_args[@]+"${go_build_args[@]}"} -trimpath -buildvcs=false -ldflags="-s -w ${ldflags_base}" -gcflags=all=-l -o "$output" "$target_pkg"
    ;;
  *)
    go build ${go_build_args[@]+"${go_build_args[@]}"} -trimpath -buildvcs=false -ldflags="-s -w ${ldflags_base}" -o "$output" "$target_pkg"
    ;;
esac
