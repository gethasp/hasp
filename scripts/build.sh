#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"
version="$(< VERSION)"

server_pkg="./apps/server/cmd/hasp"
server_mod="./apps/server/go.mod"

if [[ ! -f "$server_mod" ]]; then
  echo "No apps/server Go module exists yet. Build target is a placeholder until HASP server implementation starts." >&2
  exit 1
fi

mkdir -p bin
cd "$repo_root/apps/server"
case "$mode" in
  --debug)
    go build -ldflags="-X github.com/gethasp/hasp/apps/server/internal/runtime.buildVersion=$version" -o "$repo_root/bin/hasp" ./cmd/hasp
    ;;
  --min-size)
    go build -trimpath -buildvcs=false -ldflags="-s -w -X github.com/gethasp/hasp/apps/server/internal/runtime.buildVersion=$version" -gcflags=all=-l -o "$repo_root/bin/hasp" ./cmd/hasp
    ;;
  *)
    go build -trimpath -buildvcs=false -ldflags="-s -w -X github.com/gethasp/hasp/apps/server/internal/runtime.buildVersion=$version" -o "$repo_root/bin/hasp" ./cmd/hasp
    ;;
esac
