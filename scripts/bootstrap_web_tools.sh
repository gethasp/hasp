#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="$ROOT/apps/web"
EXPECTED_PNPM_VERSION="10.33.2"

if command -v corepack >/dev/null 2>&1; then
  corepack enable
  corepack prepare "pnpm@$EXPECTED_PNPM_VERSION" --activate
elif ! command -v pnpm >/dev/null 2>&1 || [[ "$(pnpm --version)" != "$EXPECTED_PNPM_VERSION" ]]; then
  printf 'corepack or pnpm %s is required to bootstrap the web toolchain\n' "$EXPECTED_PNPM_VERSION" >&2
  exit 1
fi

pnpm -C "$WEB_DIR" install --frozen-lockfile
