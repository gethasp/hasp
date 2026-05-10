#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="$ROOT/apps/web"
EXPECTED_PNPM_VERSION="10.33.2"
export COREPACK_HOME="${COREPACK_HOME:-$ROOT/.cache/corepack}"
export PNPM_CONFIG_MANAGE_PACKAGE_MANAGER_VERSIONS="${PNPM_CONFIG_MANAGE_PACKAGE_MANAGER_VERSIONS:-false}"
/bin/mkdir -p "$COREPACK_HOME"

if command -v corepack >/dev/null 2>&1; then
  corepack enable
  corepack prepare "pnpm@$EXPECTED_PNPM_VERSION" --activate
fi

if command -v pnpm >/dev/null 2>&1 && [[ "$(pnpm --version)" == "$EXPECTED_PNPM_VERSION" ]]; then
  pnpm -C "$WEB_DIR" install --frozen-lockfile
elif command -v npx >/dev/null 2>&1; then
  npx --yes "pnpm@$EXPECTED_PNPM_VERSION" -C "$WEB_DIR" install --frozen-lockfile
else
  printf 'corepack, pnpm %s, or npx is required to bootstrap the web toolchain\n' "$EXPECTED_PNPM_VERSION" >&2
  exit 1
fi
