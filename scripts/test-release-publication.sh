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
tmp_parent="${HASP_TEST_TMPDIR:-/tmp}"
tmp_dir="$(mktemp -d "${tmp_parent%/}/hasp-test-release-publication.XXXXXX")"
cleanup() {
  /bin/rm -rf "$tmp_dir"
}
trap cleanup EXIT

git_init_repo() {
  local repo="$1"
  /bin/mkdir -p "$repo"
  git init -b main "$repo" >/dev/null
  git -C "$repo" config user.name "HASP Test"
  git -C "$repo" config user.email "hasp@example.invalid"
  git -C "$repo" config commit.gpgsign false
}

git_init_bare() {
  local repo="$1"
  /bin/mkdir -p "$repo"
  git init --bare "$repo" >/dev/null
}

assert_file_contains() {
  local path="$1"
  local needle="$2"
  if ! grep -Fq -- "$needle" "$path"; then
    printf 'expected %s to contain %s\n' "$path" "$needle" >&2
    exit 1
  fi
}

assert_no_absolute_tar() {
  local path=""
  for path in "$@"; do
    [[ -f "$path" ]] || continue
    if grep -Fq '/usr/bin/tar' "$path"; then
      printf 'release script must resolve tar from PATH, found absolute tar in %s\n' "$path" >&2
      exit 1
    fi
  done
}

root_makefile="$ROOT/Makefile"
public_export_check="$ROOT/scripts/check-public-export.sh"
private_verify_workflow="$ROOT/.github/workflows/verify.yml"
if [[ -f "$ROOT/public/.github/workflows/release.yml" ]]; then
  release_workflow="$ROOT/public/.github/workflows/release.yml"
  public_ci_workflow="$ROOT/public/.github/workflows/ci.yml"
  public_makefile="$ROOT/public/Makefile"
  public_workflows_dir="$ROOT/public/.github/workflows"
elif [[ -f "$ROOT/.github/workflows/release.yml" ]]; then
  release_workflow="$ROOT/.github/workflows/release.yml"
  public_ci_workflow="$ROOT/.github/workflows/ci.yml"
  public_makefile="$ROOT/Makefile"
  public_workflows_dir="$ROOT/.github/workflows"
else
  release_workflow=""
  public_ci_workflow=""
  public_makefile=""
  public_workflows_dir=""
fi
if [[ -f "$public_export_check" ]]; then
  assert_file_contains "$root_makefile" 'verify-core:'
  assert_file_contains "$root_makefile" "\$(MAKE) web-check"
  assert_file_contains "$root_makefile" "HASP_DOCS_VERSIONING_PREBUILT=1 \$(MAKE) docs-versioning"
  assert_file_contains "$root_makefile" "\$(MAKE) test"
  assert_file_contains "$root_makefile" "\$(MAKE) lint"
  assert_file_contains "$root_makefile" 'verify-ci: verify-core public-export-check'
  assert_file_contains "$root_makefile" 'test-release-publication:'
  assert_file_contains "$root_makefile" 'bash ./scripts/test-release-publication.sh'
  assert_file_contains "$root_makefile" "\$(MAKE) test-release-publication"
  assert_file_contains "$public_export_check" 'make release-gate >/dev/null'
  assert_file_contains "$public_export_check" 'check-public-export-manifest.py" --list-dest'
  assert_file_contains "$public_export_check" 'unset HASP_TEST_ROOT'
  assert_file_contains "$public_export_check" 'HASP_CHECK_PUBLIC_EXPORT_SKIP_GATE'
  assert_file_contains "$public_export_check" "clean_public_runtime_artifacts \"\$TMP_DIR/public\""
  if grep -Fq "clean_public_runtime_artifacts \"\$PUBLIC_DIR\"" "$public_export_check"; then
    printf 'public export check must not delete runtime artifacts from checked-in mirror\n' >&2
    exit 1
  fi
  assert_file_contains "$public_export_check" '-x .testtmp'
  assert_file_contains "$public_export_check" '-x .testsock'
  assert_file_contains "$public_export_check" '.github/public-export-manifest.json'
  assert_file_contains "$ROOT/scripts/public-export-manifest.json" 'scripts/check-github-actions-pinning.sh'
  assert_file_contains "$ROOT/scripts/public-export-manifest.json" 'scripts/bootstrap_web_tools.sh'
  assert_file_contains "$public_makefile" 'bash ./scripts/run-public-script-tests.sh'
  assert_file_contains "$public_makefile" 'test-release-publication:'
  assert_file_contains "$public_makefile" 'bash ./scripts/test-release-publication.sh'
  assert_file_contains "$public_makefile" "\$(MAKE) test-release-publication"
  assert_file_contains "$public_makefile" 'workflow-lint:'
  assert_file_contains "$public_makefile" 'actionlint -shellcheck= -config-file .github/actionlint.yaml .github/workflows/*.yml'
  assert_file_contains "$public_makefile" 'bash ./scripts/check-github-actions-pinning.sh .github/workflows'
  assert_file_contains "$public_makefile" 'shellcheck:'
  assert_file_contains "$public_makefile" "find scripts -type f -name '*.sh' -print0 | xargs -0 shellcheck -x -P scripts"
  assert_file_contains "$public_makefile" 'verify-ci: check-links check-tidy workflow-lint shellcheck test-scripts web-check test lint'
  if grep -Fq 'test-release-publication.sh' "$ROOT/scripts/run-public-script-tests.sh"; then
    printf 'fast public script tests must not run the heavyweight release-publication harness\n' >&2
    exit 1
  fi
  if grep -Fq 'test-downloads-worker' "$root_makefile" "$ROOT/apps/web/Makefile"; then
    printf 'download Worker tests should run through apps/web package check, not duplicate Make targets\n' >&2
    exit 1
  fi
  assert_file_contains "$ROOT/scripts/bootstrap_web_tools.sh" 'EXPECTED_PNPM_VERSION="10.33.2"'
  # shellcheck disable=SC2016
  assert_file_contains "$ROOT/scripts/bootstrap_web_tools.sh" 'corepack prepare "pnpm@$EXPECTED_PNPM_VERSION" --activate'
  assert_file_contains "$ROOT/apps/web/package.json" '"check": "pnpm build && pnpm check:docs-versioning && pnpm test:downloads-worker"'
  assert_file_contains "$ROOT/scripts/conformance.sh" 'make benchmark-smoke'
  if [[ -f "$ROOT/public/scripts/conformance.sh" ]]; then
    assert_file_contains "$ROOT/public/scripts/conformance.sh" 'make benchmark-smoke'
  fi
  if grep -Fq '.github/public-export-manifest.json' "$ROOT/scripts/public-export-manifest.json"; then
    printf 'public export must not publish the private export manifest\n' >&2
    exit 1
  fi
  if [[ -e "$ROOT/public/.github/public-export-manifest.json" ]]; then
    printf 'checked-in public mirror must not contain the private export manifest\n' >&2
    exit 1
  fi
else
  assert_file_contains "$root_makefile" 'bash ./scripts/run-public-script-tests.sh'
  assert_file_contains "$root_makefile" 'verify-ci: check-links check-tidy workflow-lint shellcheck test-scripts web-check test lint'
fi
if [[ -f "$private_verify_workflow" && -f "$ROOT/scripts/check-public-export.sh" ]]; then
  fork_pr_block="$(awk '/^  fork-pr-verify:/{seen=1} seen && /^  [[:alnum:]_-]+:$/ && $0 !~ /^  fork-pr-verify:/{exit} seen{print}' "$private_verify_workflow")"
  trusted_block="$(awk '/^  verify:/{seen=1} seen && /^  [[:alnum:]_-]+:$/ && $0 !~ /^  verify:/{exit} seen{print}' "$private_verify_workflow")"
  if [[ "$fork_pr_block" != *"runs-on: ubuntu-latest"* || "$fork_pr_block" != *"run: make release-gate"* ]]; then
    printf 'private fork-pr-verify must stay on GitHub-hosted runners and run release-gate\n' >&2
    exit 1
  fi
  if [[ "$trusted_block" != *"runs-on: ubicloud-standard-2"* || "$trusted_block" != *"run: make release-gate"* ]]; then
    printf 'private trusted verify lane must stay on Ubicloud and run release-gate\n' >&2
    exit 1
  fi
fi
assert_file_contains "$ROOT/scripts/hasp-release-common.sh" 'release_tar()'
assert_no_absolute_tar \
  "$ROOT/scripts/assemble-public-release.sh" \
  "$ROOT/scripts/hasp-install-release.sh" \
  "$ROOT/scripts/hasp-release-common.sh" \
  "$ROOT/scripts/hasp-verify-release.sh" \
  "$ROOT/scripts/package-release.sh" \
  "$ROOT/scripts/release-smoke.sh"
if [[ -f "$release_workflow" ]]; then
  assert_file_contains "$public_ci_workflow" 'HASP_COVERAGE_TARGET: "100"'
  assert_file_contains "$public_ci_workflow" 'run: make release-gate'
  assert_file_contains "$public_ci_workflow" 'darwin-audit-coverage:'
  assert_file_contains "$public_ci_workflow" 'run: make coverage-audit-platform'
  assert_file_contains "$public_ci_workflow" "runs-on: ubuntu-latest"
  assert_file_contains "$public_ci_workflow" "head.repo.full_name != github.repository"
  assert_file_contains "$public_ci_workflow" "head.repo.full_name == github.repository"
  if [[ -f "$ROOT/scripts/check-public-export.sh" ]]; then
    assert_file_contains "$root_makefile" 'bash ./scripts/check-github-actions-pinning.sh .github/workflows public/.github/workflows'
  fi
  make -n -C "$(dirname "$public_makefile")" release-gate >/dev/null
  assert_file_contains "$release_workflow" 'concurrency:'
  assert_file_contains "$release_workflow" 'group: public-release'
  assert_file_contains "$release_workflow" 'cancel-in-progress: false'
  assert_file_contains "$release_workflow" 'HASP_RELEASE_BASE_URL: https://downloads.gethasp.com/hasp/releases'
  assert_file_contains "$release_workflow" 'Verify release tag commit is on main'
  assert_file_contains "$release_workflow" 'git fetch --no-tags origin main'
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" 'release_dir="dist/public-release/${GITHUB_REF_NAME}"'
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" 'metadata_path="$release_dir/release-metadata.json"'
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" 'metadata_url="https://downloads.gethasp.com/hasp/releases/${GITHUB_REF_NAME}/release-metadata.json"'
  assert_file_contains "$release_workflow" 'HASP_RELEASE_METADATA_URL'
  assert_file_contains "$release_workflow" 'metadata.get("version") != expected_version'
  assert_file_contains "$release_workflow" 'metadata.get("release_sequence") != expected_sequence'
  assert_file_contains "$release_workflow" 'retry_curl /tmp/hasp-release-metadata.json https://download.gethasp.com/api/release-metadata'
  assert_file_contains "$release_workflow" 'retry_curl /tmp/hasp-release-metadata.asc https://download.gethasp.com/api/release-metadata.asc'
  assert_file_contains "$release_workflow" 'retry_curl /tmp/hasp-release-public-key.asc https://download.gethasp.com/api/release-public-key.asc'
  assert_file_contains "$release_workflow" 'source scripts/release-public-key-trust.sh'
  assert_file_contains "$release_workflow" "release_trust_import_public_key_bundle /tmp/hasp-release-public-key.asc \"\$GNUPGHOME\" \"\$trusted_fingerprints\""
  assert_file_contains "$release_workflow" "gpgv --keyring \"\$release_trust_keyring_path\" /tmp/hasp-release-metadata.asc /tmp/hasp-release-metadata.json"
  assert_file_contains "$release_workflow" 'python3 scripts/release_targets.py shell'
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" 'https://download.gethasp.com/download/${goos}/${goarch}'
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" 'hasp_${GITHUB_REF_NAME#v}_${goos}_${goarch}.tar.gz'
  assert_file_contains "$release_workflow" 'Verify latest release mirror'
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" 'https://downloads.gethasp.com/hasp/releases/latest/${asset}'
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" 'for attempt in $(seq 1 12); do'
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" 'diff -u "$release_dir/$asset" "$tmp"'
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" 'retry_latest_diff "$asset"'
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" 'dist/public-release/${{ github.ref_name }}/*'
  if grep -Fq 'HASP_R2_PUBLISH_LATEST' "$release_workflow"; then
    printf 'release workflow must not promote latest before Worker deployment\n' >&2
    exit 1
  fi
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" 'git merge-base --is-ancestor "$GITHUB_SHA" origin/main'
  if rg -n 'uses: .*@(v|main|master|release|stable)' "$public_workflows_dir" >/dev/null; then
    printf 'public workflows must pin actions to full commit SHAs\n' >&2
    rg -n 'uses: .*@(v|main|master|release|stable)' "$public_workflows_dir" >&2 || true
    exit 1
  fi
  tag_check_line="$(grep -n 'Verify release tag commit is on main' "$release_workflow" | head -n1 | cut -d: -f1)"
  secret_line="$(grep -n 'HASP_RELEASE_GPG_PRIVATE_KEY' "$release_workflow" | head -n1 | cut -d: -f1)"
  if [[ -z "$tag_check_line" || -z "$secret_line" || "$tag_check_line" -ge "$secret_line" ]]; then
    printf 'release workflow must verify tag ancestry before exposing signing secrets\n' >&2
    exit 1
  fi
  release_gate_line="$(grep -n 'make release-gate' "$release_workflow" | head -n1 | cut -d: -f1)"
  if [[ -z "$release_gate_line" || -z "$secret_line" || "$release_gate_line" -ge "$secret_line" ]]; then
    printf 'release workflow must run release-gate before exposing signing secrets\n' >&2
    exit 1
  fi
  publish_r2_line="$(grep -n '^  publish-r2:' "$release_workflow" | head -n1 | cut -d: -f1)"
  first_r2_secret_line="$(grep -n 'HASP_R2_ENDPOINT:' "$release_workflow" | head -n1 | cut -d: -f1)"
  if [[ -z "$publish_r2_line" || -z "$first_r2_secret_line" || "$first_r2_secret_line" -le "$publish_r2_line" ]]; then
    printf 'release workflow must keep R2 credentials scoped to publish-r2\n' >&2
    exit 1
  fi
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" ': "${HASP_R2_ENDPOINT:?HASP_R2_ENDPOINT is required}"'
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" ': "${HASP_R2_BUCKET:?HASP_R2_BUCKET is required}"'
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" ': "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID is required}"'
  # shellcheck disable=SC2016
  assert_file_contains "$release_workflow" ': "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY is required}"'
  if grep -Fq "skipping R2 publication" "$release_workflow"; then
    printf 'release workflow must fail, not skip, when R2 publication is required\n' >&2
    exit 1
  fi
  if grep -Fq "skipping published Homebrew smoke" "$release_workflow"; then
    printf 'release workflow must not skip published Homebrew smoke when R2 publication is required\n' >&2
    exit 1
  fi
  if grep -Eq 'x-access-token:|HASP_HOMEBREW_TAP_TOKEN@' "$release_workflow"; then
    printf 'release workflow must not put the Homebrew tap token in a clone URL\n' >&2
    exit 1
  fi
  assert_file_contains "$release_workflow" "GIT_ASKPASS=\"\$askpass\" GIT_TERMINAL_PROMPT=0 git clone https://github.com/gethasp/homebrew-tap.git tap-repo"
  worker_smoke_line="$(grep -n 'Smoke download Worker release endpoint' "$release_workflow" | head -n1 | cut -d: -f1)"
  promote_latest_line="$(grep -n 'Promote latest release mirror' "$release_workflow" | head -n1 | cut -d: -f1)"
  verify_latest_line="$(grep -n 'Verify latest release mirror' "$release_workflow" | head -n1 | cut -d: -f1)"
  if [[ -z "$worker_smoke_line" || -z "$promote_latest_line" || -z "$verify_latest_line" ||
    "$worker_smoke_line" -ge "$promote_latest_line" || "$promote_latest_line" -ge "$verify_latest_line" ]]; then
    printf 'release workflow must smoke the Worker before promoting latest\n' >&2
    exit 1
  fi
  publish_tap_block="$(awk '/^  publish-homebrew-tap:/{seen=1} seen && /^  [[:alnum:]_-]+:$/ && $0 !~ /^  publish-homebrew-tap:/{exit} seen{print}' "$release_workflow")"
  if [[ "$publish_tap_block" != *"      - deploy-download-worker"* || "$publish_tap_block" != *"      - homebrew-formula-smoke"* ]]; then
    printf 'Homebrew tap publication must wait for Worker and formula smoke\n' >&2
    exit 1
  fi
  assert_file_contains "$release_workflow" 'published-homebrew-tap-smoke:'
  assert_file_contains "$release_workflow" 'brew tap gethasp/hasp https://github.com/gethasp/homebrew-tap.git'
  assert_file_contains "$release_workflow" 'brew install gethasp/hasp/hasp'
  github_release_block="$(awk '/^  github-release:/{seen=1} seen && /^  [[:alnum:]_-]+:$/ && $0 !~ /^  github-release:/{exit} seen{print}' "$release_workflow")"
  if [[ "$github_release_block" != *"      - published-homebrew-tap-smoke"* ]]; then
    printf 'GitHub Release publication must wait for published tap smoke\n' >&2
    exit 1
  fi
fi

public_repo="$tmp_dir/public"
public_remote="$tmp_dir/public-origin.git"
if [[ -f "$ROOT/scripts/release-public-hasp.sh" && -f "$ROOT/scripts/export-public-hasp.py" ]]; then
  # shellcheck disable=SC2016
  assert_file_contains "$ROOT/scripts/release-public-hasp.sh" 'git -C "$ROOT" status --porcelain --untracked-files=all'
  # shellcheck disable=SC2016
  assert_file_contains "$ROOT/scripts/release-public-hasp.sh" 'SOURCE_REMOTE="${HASP_SOURCE_REMOTE:-origin}"'
  # shellcheck disable=SC2016
  assert_file_contains "$ROOT/scripts/release-public-hasp.sh" 'SOURCE_PROVENANCE_REF="${HASP_SOURCE_PROVENANCE_REF:-}"'
  # shellcheck disable=SC2016
  assert_file_contains "$ROOT/scripts/release-public-hasp.sh" 'git -C "$ROOT" fetch --no-tags "$SOURCE_REMOTE" "+$SOURCE_REMOTE_BRANCH:refs/remotes/$SOURCE_REMOTE/$SOURCE_REMOTE_BRANCH"'
  assert_file_contains "$ROOT/scripts/release-public-hasp.sh" 'required source provenance could not be resolved'
  # shellcheck disable=SC2016
  assert_file_contains "$ROOT/scripts/release-public-hasp.sh" 'git -C "$ROOT" merge-base --is-ancestor "$SOURCE_COMMIT" "$provenance_ref"'
  if grep -Eq 'HASP_RELEASE_PUBLIC_SKIP_(SOURCE_PROVENANCE|EXPORT_CHECK)' "$ROOT/scripts/release-public-hasp.sh"; then
    printf 'release-public-hasp must not expose production release bypass env vars\n' >&2
    exit 1
  fi

  source_repo="$tmp_dir/source"
  source_remote="$tmp_dir/source-origin.git"
  git_init_bare "$source_remote"
  /bin/mkdir -p "$source_repo/scripts"
  /bin/cp -f "$ROOT/scripts/release-public-hasp.sh" "$source_repo/scripts/release-public-hasp.sh"
  /bin/cp -f "$ROOT/scripts/hasp-release-common.sh" "$source_repo/scripts/hasp-release-common.sh"
  /bin/cp -f "$ROOT/scripts/release-public-key-trust.sh" "$source_repo/scripts/release-public-key-trust.sh"
  /bin/cp -f "$ROOT/scripts/release-trusted-gpg-fingerprints.txt" "$source_repo/scripts/release-trusted-gpg-fingerprints.txt"
  {
    printf '%s\n' '#!/usr/bin/env bash'
    printf '%s\n' 'set -euo pipefail'
    printf '%s\n' ':'
  } >"$source_repo/scripts/check-public-export.sh"
  cat >"$source_repo/scripts/export-public-hasp.py" <<'PY'
#!/usr/bin/env python3
import argparse
import pathlib
import shutil

parser = argparse.ArgumentParser()
parser.add_argument("--dest", required=True)
parser.add_argument("--clean", action="store_true")
args = parser.parse_args()
dest = pathlib.Path(args.dest)
if args.clean:
    for child in dest.iterdir() if dest.exists() else []:
        if child.name == ".git":
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
dest.mkdir(parents=True, exist_ok=True)
(dest / "README.md").write_text("public release fixture\n", encoding="utf-8")
PY
  chmod +x "$source_repo/scripts/release-public-hasp.sh" "$source_repo/scripts/check-public-export.sh" "$source_repo/scripts/export-public-hasp.py"
  git_init_repo "$source_repo"
  git -C "$source_repo" add -A
  git -C "$source_repo" commit -m "source" >/dev/null
  git -C "$source_repo" remote add origin "$source_remote"
  git -C "$source_repo" push origin main >/dev/null

  git_init_bare "$public_remote"
  git_init_repo "$public_repo"
  git -C "$public_repo" remote add origin "$public_remote"

  dirty_public="$tmp_dir/dirty-public"
  git_init_repo "$dirty_public"
  printf 'local work\n' >"$dirty_public/LOCAL_ONLY.txt"
  dirty_public_log="$tmp_dir/dirty-public.log"
  if HASP_CHECK_PUBLIC_EXPORT_SKIP_GATE=1 bash "$source_repo/scripts/release-public-hasp.sh" "$dirty_public" "v0.0.0-dirty" >/dev/null 2>"$dirty_public_log"; then
    printf 'expected release-public-hasp to reject a dirty public repo\n' >&2
    exit 1
  fi
  if ! grep -Fq 'public release repo must be clean before export' "$dirty_public_log"; then
    printf 'dirty public repo failure did not report cleanliness cause:\n' >&2
    cat "$dirty_public_log" >&2
    exit 1
  fi

  HASP_CHECK_PUBLIC_EXPORT_SKIP_GATE=1 \
    HASP_PRIVATE_SOURCE_REPO="ssh://git@git.internal.example.com/team/private-hasp.git" \
    bash "$source_repo/scripts/release-public-hasp.sh" "$public_repo" "v0.0.0-test" --push >/dev/null

  public_head="$(git -C "$public_repo" rev-parse HEAD)"
  remote_tag_commit="$(
    git -C "$public_repo" ls-remote --tags origin "refs/tags/v0.0.0-test" "refs/tags/v0.0.0-test^{}" |
      awk '$2 ~ /\^\{\}$/ { peeled = $1 } $2 !~ /\^\{\}$/ { direct = $1 } END { print peeled ? peeled : direct }'
  )"
  if [[ "$remote_tag_commit" != "$public_head" ]]; then
    printf 'remote public release tag points at %s, want %s\n' "$remote_tag_commit" "$public_head" >&2
    exit 1
  fi
  commit_body="$(git -C "$public_repo" log -1 --format=%B)"
  if [[ "$commit_body" == *"git.internal.example.com"* ]]; then
    printf 'public release commit leaked private source repo: %s\n' "$commit_body" >&2
    exit 1
  fi
  [[ "$commit_body" == *"Source-Repo: private-monorepo"* ]]

  printf 'unpushed\n' >"$source_repo/UNPUSHED.txt"
  git -C "$source_repo" add UNPUSHED.txt
  git -C "$source_repo" commit -m "unpushed" >/dev/null
  git -C "$source_repo" update-ref refs/remotes/origin/main HEAD
  stale_ref_public="$tmp_dir/stale-ref-public"
  git_init_repo "$stale_ref_public"
  stale_ref_log="$tmp_dir/stale-ref.log"
  if HASP_CHECK_PUBLIC_EXPORT_SKIP_GATE=1 bash "$source_repo/scripts/release-public-hasp.sh" "$stale_ref_public" "v0.0.0-stale-ref" >/dev/null 2>"$stale_ref_log"; then
    printf 'expected release-public-hasp to reject an unpushed source commit despite stale local tracking ref\n' >&2
    exit 1
  fi
  if ! grep -Fq 'source commit is not reachable from refs/remotes/origin/main' "$stale_ref_log"; then
    printf 'stale local tracking ref failure did not report ancestry cause:\n' >&2
    cat "$stale_ref_log" >&2
    exit 1
  fi
  git -C "$source_repo" reset --hard HEAD~1 >/dev/null
  git -C "$source_repo" fetch --no-tags origin main:refs/remotes/origin/main >/dev/null

  offline_source="$tmp_dir/offline-source"
  git -C "$source_repo" checkout-index -a --prefix="$offline_source/"
  {
    printf '%s\n' '#!/usr/bin/env bash'
    printf '%s\n' 'set -euo pipefail'
    printf '%s\n' ':'
  } >"$offline_source/scripts/check-public-export.sh"
  git_init_repo "$offline_source"
  git -C "$offline_source" add -A
  git -C "$offline_source" commit -m "offline source" >/dev/null
  offline_public="$tmp_dir/offline-public"
  git_init_repo "$offline_public"
  provenance_log="$tmp_dir/offline-provenance.log"
  if HASP_CHECK_PUBLIC_EXPORT_SKIP_GATE=1 bash "$offline_source/scripts/release-public-hasp.sh" "$offline_public" "v0.0.2-offline" >/dev/null 2>"$provenance_log"; then
    printf 'expected release-public-hasp to reject required provenance without a source remote\n' >&2
    exit 1
  fi
  if ! grep -Fq 'required source provenance could not be resolved' "$provenance_log"; then
    printf 'required provenance failure did not report provenance-specific cause:\n' >&2
    cat "$provenance_log" >&2
    exit 1
  fi

  mismatch_repo="$tmp_dir/mismatch-public"
  mismatch_remote="$tmp_dir/mismatch-origin.git"
  git_init_bare "$mismatch_remote"
  git_init_repo "$mismatch_repo"
  git -C "$mismatch_repo" remote add origin "$mismatch_remote"
  printf 'old\n' >"$mismatch_repo/old.txt"
  git -C "$mismatch_repo" add old.txt
  git -C "$mismatch_repo" commit -m old >/dev/null
  git -C "$mismatch_repo" tag -a "v0.0.1-test" -m "old"
  git -C "$mismatch_repo" push --atomic origin main "refs/tags/v0.0.1-test" >/dev/null
  before_tag="$(
    git -C "$mismatch_repo" ls-remote --tags origin "refs/tags/v0.0.1-test" "refs/tags/v0.0.1-test^{}" |
      awk '$2 ~ /\^\{\}$/ { peeled = $1 } $2 !~ /\^\{\}$/ { direct = $1 } END { print peeled ? peeled : direct }'
  )"
  if HASP_CHECK_PUBLIC_EXPORT_SKIP_GATE=1 bash "$source_repo/scripts/release-public-hasp.sh" "$mismatch_repo" "v0.0.1-test" --push >/dev/null 2>&1; then
    printf 'expected release-public-hasp to reject existing mismatched release tag\n' >&2
    exit 1
  fi
  after_tag="$(
    git -C "$mismatch_repo" ls-remote --tags origin "refs/tags/v0.0.1-test" "refs/tags/v0.0.1-test^{}" |
      awk '$2 ~ /\^\{\}$/ { peeled = $1 } $2 !~ /\^\{\}$/ { direct = $1 } END { print peeled ? peeled : direct }'
  )"
  if [[ "$after_tag" != "$before_tag" ]]; then
    printf 'release-public-hasp moved existing remote tag: before=%s after=%s\n' "$before_tag" "$after_tag" >&2
    exit 1
  fi
fi

formula="$tmp_dir/hasp.rb"
tap_repo="$tmp_dir/tap"
printf 'class Hasp < Formula\nend\n' >"$formula"
git_init_repo "$tap_repo"
touch "$tap_repo/README.md"
git -C "$tap_repo" add README.md
git -C "$tap_repo" commit -m initial >/dev/null
bash "$ROOT/scripts/publish-homebrew-tap.sh" "$formula" "$tap_repo" "v0.0.0-test" >/dev/null
assert_file_contains "$tap_repo/Formula/hasp.rb" "class Hasp"
git -C "$tap_repo" log -1 --format=%s | grep -qx "Update HASP formula for v0.0.0-test"

release_dir="$tmp_dir/release"
/bin/mkdir -p "$release_dir"
printf 'artifact\n' >"$release_dir/artifact"
printf 'nested\n' >"$release_dir/nested-artifact"
dry_run="$(
  HASP_R2_BUCKET="hasp-test" \
  HASP_R2_ENDPOINT="https://r2.example.invalid" \
  AWS_ACCESS_KEY_ID="test" \
  AWS_SECRET_ACCESS_KEY="test" \
  HASP_R2_PROMOTE_LATEST=1 \
  bash "$ROOT/scripts/publish-release-to-r2.sh" --dry-run "$release_dir" "v0.0.0-test"
)"
[[ "$dry_run" == *"s3://hasp-test/hasp/releases/v0.0.0-test/"* ]]
[[ "$dry_run" == *"s3://hasp-test/hasp/releases/latest/"* ]]
[[ "$dry_run" == *"s3api put-object"* ]]
[[ "$dry_run" == *"--if-none-match \\*"* ]]
if HASP_R2_BUCKET="hasp-test" \
  HASP_R2_ENDPOINT="https://r2.example.invalid" \
  AWS_ACCESS_KEY_ID="test" \
  AWS_SECRET_ACCESS_KEY="test" \
  HASP_R2_PUBLISH_LATEST=1 \
  bash "$ROOT/scripts/publish-release-to-r2.sh" --dry-run "$release_dir" "v0.0.0-test" >/dev/null 2>&1; then
  printf 'deprecated HASP_R2_PUBLISH_LATEST unexpectedly succeeded\n' >&2
  exit 1
fi

stub_bin="$tmp_dir/bin"
aws_log="$tmp_dir/aws.log"
/bin/mkdir -p "$stub_bin"
{
  printf '%s\n' '#!/usr/bin/env bash'
  # shellcheck disable=SC2016
  printf '%s\n' 'printf '"'"'%s\n'"'"' "$*" >>"${HASP_AWS_STUB_LOG:?}"'
  printf '%s\n' 'if [[ "$*" == *"list-objects-v2"* ]]; then'
  # shellcheck disable=SC2016
  printf '%s\n' '  printf '"'"'%s\n'"'"' "${HASP_AWS_STUB_LIST_RESULT:-None}"'
  printf '%s\n' 'fi'
} >"$stub_bin/aws"
chmod +x "$stub_bin/aws"

: >"$aws_log"
PATH="$stub_bin:$PATH" \
  HASP_AWS_STUB_LOG="$aws_log" \
  HASP_AWS_STUB_LIST_RESULT="None" \
  HASP_R2_BUCKET="hasp-test" \
  HASP_R2_ENDPOINT="https://r2.example.invalid" \
  AWS_ACCESS_KEY_ID="test" \
  AWS_SECRET_ACCESS_KEY="test" \
  bash "$ROOT/scripts/publish-release-to-r2.sh" "$release_dir" "v0.0.0-test" >/dev/null
grep -Fq "s3api list-objects-v2" "$aws_log"
grep -Fq "s3api put-object" "$aws_log"
grep -Fq -- "--if-none-match *" "$aws_log"

: >"$aws_log"
if PATH="$stub_bin:$PATH" \
  HASP_AWS_STUB_LOG="$aws_log" \
  HASP_AWS_STUB_LIST_RESULT="hasp/releases/v0.0.0-test/artifact" \
  HASP_R2_BUCKET="hasp-test" \
  HASP_R2_ENDPOINT="https://r2.example.invalid" \
  AWS_ACCESS_KEY_ID="test" \
  AWS_SECRET_ACCESS_KEY="test" \
  bash "$ROOT/scripts/publish-release-to-r2.sh" "$release_dir" "v0.0.0-test" >/dev/null 2>&1; then
  printf 'expected R2 publisher to reject non-empty immutable release prefix\n' >&2
  exit 1
fi
if grep -Fq "s3api put-object" "$aws_log"; then
  printf 'R2 publisher uploaded into non-empty immutable release prefix\n' >&2
  exit 1
fi

printf 'release publication checks passed\n'
