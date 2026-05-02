#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
version="$(< VERSION)"

# Compute build metadata. Fall back to "unknown" when git is unavailable
# (e.g. building from a source tarball without a .git directory).
commit="$(git rev-parse --short=10 HEAD 2>/dev/null || echo unknown)"
build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

pkg="github.com/gethasp/hasp/apps/server/internal/runtime"
release_pkg="github.com/gethasp/hasp/apps/server/internal/release"
upgrade_trust_roots="${HASP_UPGRADE_TRUST_ROOTS_HEX:-}"
if [[ -n "$upgrade_trust_roots" && ! "$upgrade_trust_roots" =~ ^[0-9a-fA-F]{64}(,[0-9a-fA-F]{64})*$ ]]; then
  echo "HASP_UPGRADE_TRUST_ROOTS_HEX must be one or more comma-separated 64-hex Ed25519 public keys" >&2
  exit 1
fi
ldflags_base="\
-X ${pkg}.Version=${version} \
-X ${pkg}.Commit=${commit} \
-X ${pkg}.BuildDate=${build_date}"
if [[ -n "$upgrade_trust_roots" ]]; then
  ldflags_base+=" -X ${release_pkg}.pinnedKeysHex=${upgrade_trust_roots}"
fi

server_mod="./apps/server/go.mod"

if [[ ! -f "$server_mod" ]]; then
  echo "No apps/server Go module exists yet. Build target is a placeholder until HASP server implementation starts." >&2
  exit 1
fi

mkdir -p bin
cd "$repo_root/apps/server"
case "$mode" in
  --debug)
    go build -ldflags="${ldflags_base}" -o "$repo_root/bin/hasp" ./cmd/hasp
    ;;
  --min-size)
    go build -trimpath -buildvcs=false -ldflags="-s -w ${ldflags_base}" -gcflags=all=-l -o "$repo_root/bin/hasp" ./cmd/hasp
    ;;
  *)
    go build -trimpath -buildvcs=false -ldflags="-s -w ${ldflags_base}" -o "$repo_root/bin/hasp" ./cmd/hasp
    ;;
esac
