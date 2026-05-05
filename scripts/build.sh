#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
version="$(< VERSION)"
mode=""
output="${HASP_BUILD_OUTPUT:-}"
target_pkg="./cmd/hasp"

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
upgrade_trust_roots="${HASP_UPGRADE_TRUST_ROOTS_HEX:-}"
if [[ -n "$upgrade_trust_roots" && ! "$upgrade_trust_roots" =~ ^[0-9a-fA-F]{64}(,[0-9a-fA-F]{64})*$ ]]; then
  echo "HASP_UPGRADE_TRUST_ROOTS_HEX must be one or more comma-separated 64-hex Ed25519 public keys" >&2
  exit 1
fi
ldflags_base="\
-X ${runtime_pkg}.Version=${version} \
-X ${runtime_pkg}.Commit=${commit} \
-X ${runtime_pkg}.BuildDate=${build_date}"
if [[ -n "$upgrade_trust_roots" ]]; then
  ldflags_base+=" -X ${release_pkg}.pinnedKeysHex=${upgrade_trust_roots}"
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
case "$mode" in
  --debug)
    go build -ldflags="${ldflags_base}" -o "$output" "$target_pkg"
    ;;
  --min-size)
    go build -trimpath -buildvcs=false -ldflags="-s -w ${ldflags_base}" -gcflags=all=-l -o "$output" "$target_pkg"
    ;;
  *)
    go build -trimpath -buildvcs=false -ldflags="-s -w ${ldflags_base}" -o "$output" "$target_pkg"
    ;;
esac
