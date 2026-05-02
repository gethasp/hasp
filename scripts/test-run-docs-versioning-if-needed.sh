#!/usr/bin/env bash
set -euo pipefail

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${HASP_TEST_ROOT:-}" ]]; then
  ROOT="$(cd "$HASP_TEST_ROOT" && pwd)"
elif [[ -f "$script_root/VERSION" && -f "$script_root/apps/server/go.mod" && ! -f "$script_root/scripts/export-public-hasp.py" ]]; then
  ROOT="$script_root"
elif ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  :
else
  ROOT="$script_root"
fi
SCRIPT="$ROOT/scripts/run-docs-versioning-if-needed.sh"
/bin/mkdir -p "$ROOT/dist"
tmp_dir="$(mktemp -d "$ROOT/dist/test-run-docs-versioning.XXXXXX")"
cleanup() {
  /bin/rm -rf "$tmp_dir"
}
trap cleanup EXIT
unset HASP_DOCS_VERSIONING_FORCE
unset HASP_DOCS_VERSIONING_SKIP
stub_bin="$tmp_dir/bin"
pnpm_calls="$tmp_dir/pnpm.calls"
/bin/mkdir -p "$stub_bin"
{
  printf '%s\n' '#!/usr/bin/env bash'
  # shellcheck disable=SC2016
  printf '%s\n' 'printf "%s\n" "$*" >>"${HASP_PNPM_STUB_LOG:?}"'
} >"$stub_bin/pnpm"
chmod +x "$stub_bin/pnpm"

expect_check() {
  local expected="$1"
  shift
  local actual
  actual="$("$@" "$SCRIPT" --check)"
  if [[ "$actual" != "$expected" ]]; then
    printf 'docs-versioning check mismatch: actual=%s expected=%s command=%s\n' "$actual" "$expected" "$*" >&2
    exit 1
  fi
}

expect_run() {
  local expected_pnpm="$1"
  shift
  local output
  : >"$pnpm_calls"
  if ! output="$(PATH="$stub_bin:$PATH" HASP_PNPM_STUB_LOG="$pnpm_calls" "$@" "$SCRIPT" 2>&1)"; then
    printf 'docs-versioning run failed: command=%s\n%s\n' "$*" "$output" >&2
    exit 1
  fi

  local actual_pnpm=false
  if [[ -s "$pnpm_calls" ]]; then
    actual_pnpm=true
  fi
  local expected_called
  if [[ "$expected_pnpm" == "prebuilt" ]]; then
    expected_called=true
  else
    expected_called="$expected_pnpm"
  fi
  if [[ "$actual_pnpm" != "$expected_called" ]]; then
    printf 'docs-versioning run mismatch: pnpm_called=%s expected=%s command=%s output=%s\n' "$actual_pnpm" "$expected_pnpm" "$*" "$output" >&2
    exit 1
  fi
  if [[ "$expected_pnpm" == "true" ]] && {
    ! grep -qx -- '-C apps/web build' "$pnpm_calls" ||
    ! grep -qx -- '-C apps/web test:docs-versioning' "$pnpm_calls"
  }; then
    printf 'docs-versioning run called unexpected pnpm command:\n' >&2
    cat "$pnpm_calls" >&2
    exit 1
  fi
  if [[ "$expected_pnpm" == "prebuilt" ]] && {
    grep -qx -- '-C apps/web build' "$pnpm_calls" ||
    ! grep -qx -- '-C apps/web test:docs-versioning' "$pnpm_calls"
  }; then
    printf 'prebuilt docs-versioning run called unexpected pnpm command:\n' >&2
    cat "$pnpm_calls" >&2
    exit 1
  fi
  if [[ "$expected_pnpm" == "false" && "$output" != *"docs-versioning skipped"* ]]; then
    printf 'docs-versioning skip output missing: command=%s output=%s\n' "$*" "$output" >&2
    exit 1
  fi
}

write_changed_paths() {
  local name="$1"
  shift
  local path_file="$tmp_dir/$name.paths"
  printf '%s\n' "$@" >"$path_file"
  printf '%s\n' "$path_file"
}

server_paths="$(write_changed_paths server-only apps/server/main.go)"
expect_check false env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$server_paths" bash
expect_check true env HASP_DOCS_VERSIONING_FORCE=1 HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$server_paths" bash
expect_check false env HASP_DOCS_VERSIONING_SKIP=1 HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$server_paths" bash
expect_run false env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$server_paths" bash
expect_run true env HASP_DOCS_VERSIONING_FORCE=1 HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$server_paths" bash
expect_run false env HASP_DOCS_VERSIONING_SKIP=1 HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$server_paths" bash

docs_paths="$(write_changed_paths docs-change public/docs/install.md)"
expect_check true env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$docs_paths" bash
expect_run true env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$docs_paths" bash
expect_run prebuilt env HASP_DOCS_VERSIONING_PREBUILT=1 HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$docs_paths" bash
expect_run false env HASP_DOCS_VERSIONING_SKIP=1 HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$docs_paths" bash

public_root_paths="$(write_changed_paths public-root-change README.md docs/install.md)"
expect_check true env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$public_root_paths" bash
expect_run true env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$public_root_paths" bash

metadata_paths="$(write_changed_paths metadata-change public/docs-metadata.json)"
expect_check false env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$metadata_paths" bash
expect_run false env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$metadata_paths" bash

snapshot_paths="$(write_changed_paths snapshot-change public/docs-versions/v0.1.39/manifest.json)"
expect_check false env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$snapshot_paths" bash
expect_run false env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$snapshot_paths" bash

web_paths="$(write_changed_paths web-nondocs-change apps/web/downloads/src/worker.js)"
expect_check false env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$web_paths" bash
expect_run false env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$web_paths" bash

catalog_paths="$(write_changed_paths docs-catalog-change apps/web/src/_data/docs-specs.json)"
expect_check true env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$catalog_paths" bash
expect_run true env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$catalog_paths" bash

template_paths="$(write_changed_paths docs-template-change apps/web/src/docs.njk)"
expect_check true env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$template_paths" bash
expect_run true env HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$template_paths" bash

if [[ -d "$ROOT/public" && -f "$ROOT/public/scripts/run-docs-versioning-if-needed.sh" ]]; then
  public_paths="$(write_changed_paths standalone-public-change README.md docs/install.md)"
  expect_check true env HASP_TEST_ROOT="$ROOT/public" HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$public_paths" bash
  expect_run true env HASP_TEST_ROOT="$ROOT/public" HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$public_paths" bash
  private_paths_in_public="$(write_changed_paths standalone-private-form public/README.md public/docs/install.md)"
  expect_check true env HASP_TEST_ROOT="$ROOT/public" HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$private_paths_in_public" bash
  expect_run true env HASP_TEST_ROOT="$ROOT/public" HASP_DOCS_VERSIONING_CHANGED_PATHS_FILE="$private_paths_in_public" bash
fi

git_init_docs_fixture() {
  local name="$1"
  local fixture="$tmp_dir/$name"
  /bin/mkdir -p \
    "$fixture/scripts" \
    "$fixture/apps/server" \
    "$fixture/apps/web/src/_data" \
    "$fixture/apps/web/src" \
    "$fixture/docs"
  /bin/cp -f "$SCRIPT" "$fixture/scripts/run-docs-versioning-if-needed.sh"
  /bin/cp -f "$ROOT/scripts/docs-versioning-inputs.txt" "$fixture/scripts/docs-versioning-inputs.txt"
  printf '# fixture\n' >"$fixture/README.md"
  printf '# install\n' >"$fixture/docs/install.md"
  printf 'package main\n' >"$fixture/apps/server/main.go"
  printf '[]\n' >"$fixture/apps/web/src/_data/docs-specs.json"
  printf 'docs template\n' >"$fixture/apps/web/src/docs.njk"
  if ! git init -q -b main "$fixture" 2>/dev/null; then
    git init -q "$fixture"
    git -C "$fixture" checkout -q -b main
  fi
  git -C "$fixture" config user.name "HASP Test"
  git -C "$fixture" config user.email "hasp@example.invalid"
  git -C "$fixture" config commit.gpgsign false
  git -C "$fixture" add .
  git -C "$fixture" commit -qm initial
  printf '%s\n' "$fixture"
}

git_commit_fixture_change() {
  local fixture="$1"
  local path="$2"
  local message="$3"
  /bin/mkdir -p "$(dirname "$fixture/$path")"
  printf '%s\n' "$message" >>"$fixture/$path"
  git -C "$fixture" add "$path"
  git -C "$fixture" commit -qm "$message"
}

expect_git_check() {
  local fixture="$1"
  local expected="$2"
  shift 2
  local actual
  actual="$(cd "$fixture" && env -u HASP_TEST_ROOT -u HASP_DOCS_VERSIONING_BASE "$@" bash scripts/run-docs-versioning-if-needed.sh --check)"
  if [[ "$actual" != "$expected" ]]; then
    printf 'docs-versioning git diff check mismatch: fixture=%s actual=%s expected=%s env=%s\n' "$fixture" "$actual" "$expected" "$*" >&2
    exit 1
  fi
}

origin_fixture="$(git_init_docs_fixture origin-main-fixture)"
git -C "$origin_fixture" update-ref refs/remotes/origin/main HEAD
git_commit_fixture_change "$origin_fixture" apps/server/main.go server-change
expect_git_check "$origin_fixture" false
git_commit_fixture_change "$origin_fixture" docs/install.md docs-change
expect_git_check "$origin_fixture" true

head_fixture="$(git_init_docs_fixture head-fallback-fixture)"
git_commit_fixture_change "$head_fixture" apps/server/main.go server-change
expect_git_check "$head_fixture" false
git_commit_fixture_change "$head_fixture" README.md readme-change
expect_git_check "$head_fixture" true

base_fixture="$(git_init_docs_fixture explicit-base-fixture)"
base_sha="$(git -C "$base_fixture" rev-parse HEAD)"
git_commit_fixture_change "$base_fixture" apps/server/main.go server-change
expect_git_check "$base_fixture" false HASP_DOCS_VERSIONING_BASE="$base_sha"
git_commit_fixture_change "$base_fixture" apps/web/src/_data/docs-specs.json catalog-change
expect_git_check "$base_fixture" true HASP_DOCS_VERSIONING_BASE="$base_sha"

plain_root="$tmp_dir/plain-root"
/bin/mkdir -p "$plain_root/scripts" "$plain_root/apps/web"
/bin/cp -f "$SCRIPT" "$plain_root/scripts/run-docs-versioning-if-needed.sh"
/bin/cp -f "$ROOT/scripts/docs-versioning-inputs.txt" "$plain_root/scripts/docs-versioning-inputs.txt"
(
  cd "$plain_root"
  actual="$(env -u HASP_TEST_ROOT GIT_CEILING_DIRECTORIES="$tmp_dir" bash scripts/run-docs-versioning-if-needed.sh --check)"
  if [[ "$actual" != "true" ]]; then
    printf 'docs-versioning check should run outside git worktrees, got %s\n' "$actual" >&2
    exit 1
  fi
  : >"$pnpm_calls"
  env -u HASP_TEST_ROOT GIT_CEILING_DIRECTORIES="$tmp_dir" PATH="$stub_bin:$PATH" HASP_PNPM_STUB_LOG="$pnpm_calls" bash scripts/run-docs-versioning-if-needed.sh >/dev/null
  if ! grep -qx -- '-C apps/web build' "$pnpm_calls" || ! grep -qx -- '-C apps/web test:docs-versioning' "$pnpm_calls"; then
    printf 'docs-versioning no-git fallback did not run expected pnpm command:\n' >&2
    cat "$pnpm_calls" >&2
    exit 1
  fi
)

printf 'docs-versioning path and run gate checks passed\n'
