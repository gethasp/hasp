#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./hasp-release-common.sh
source "$script_dir/hasp-release-common.sh"

repo_root="$(git -C "$script_dir/.." rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

version="$(< VERSION)"
os_name="${HASP_TARGET_OS:-$(go env GOOS)}"
arch_name="${HASP_TARGET_ARCH:-$(go env GOARCH)}"
artifact_name="hasp_${version}_${os_name}_${arch_name}"
release_root="${HASP_RELEASE_ROOT:-$repo_root/dist/release}"
artifact_dir="$release_root/$artifact_name"
tarball="$release_root/${artifact_name}.tar.gz"
checksum_path="$release_root/SHA256SUMS"
checksum_sig_path="$release_root/SHA256SUMS.asc"
public_key_path="$release_root/hasp-release-public-key.asc"
tarball_sig_path="$release_root/${artifact_name}.tar.gz.asc"
binary_sig_path="$release_root/${artifact_name}_bin.asc"
fingerprint_path="$release_root/RELEASE-SIGNING-FINGERPRINT.txt"
formula_dir="$release_root/Formula"
formula_path="$formula_dir/hasp.rb"

/bin/rm -rf "$artifact_dir" "$tarball" "$checksum_path" "$checksum_sig_path" "$public_key_path" "$tarball_sig_path" "$binary_sig_path" "$fingerprint_path" "$formula_dir"
/bin/mkdir -p "$artifact_dir/bin" "$artifact_dir/agent-profiles" "$artifact_dir/profiles" "$artifact_dir/scripts" "$formula_dir"

bash ./scripts/build.sh
/bin/cp -f "$repo_root/bin/hasp" "$artifact_dir/bin/hasp"
/bin/cp -f "$repo_root/LICENSE" "$artifact_dir/LICENSE"
bash ./scripts/generate-supply-chain-artifacts.sh "$artifact_dir" >/dev/null

packaged_scripts=(
  hasp-common.sh
  hasp-release-common.sh
  hasp-install-release.sh
  hasp-upgrade-release.sh
  hasp-uninstall-release.sh
  hasp-sign-release.sh
  hasp-verify-release.sh
  generate-supply-chain-artifacts.sh
  render-homebrew-formula.sh
  hasp-install-hooks.sh
  hasp-pre-commit.sh
  hasp-pre-push.sh
  hasp-deploy.sh
)
for script_name in "${packaged_scripts[@]}"; do
  /bin/cp -f "$repo_root/scripts/$script_name" "$artifact_dir/scripts/"
done
/bin/cp -f "$repo_root/docs/agent-profiles/"*.md "$artifact_dir/agent-profiles/"
/bin/cp -f "$repo_root/apps/server/profiles/"*.json "$artifact_dir/profiles/"

cat >"$artifact_dir/RELEASE_MANIFEST" <<EOF
artifact_name_expected='$artifact_name'
name='$artifact_name'
version='$version'
os='$os_name'
arch='$arch_name'
release_files=(
  'LICENSE'
  'README.md'
  'QUICKSTART.md'
  'OPERATOR_GUIDE.md'
  'PRODUCTION_GUIDE.md'
  'RELEASE_MANIFEST'
  'CODE_SIGNING_STATUS.json'
  'REPRODUCIBLE_BUILD.json'
  'sbom.spdx.json'
  'slsa-provenance.json'
  'bin/hasp'
  'agent-profiles/README.md'
  'agent-profiles/generic.md'
  'profiles/aider.json'
  'profiles/claude-code.json'
  'profiles/codex-cli.json'
  'profiles/cursor.json'
  'profiles/hermes.json'
  'profiles/openclaw.json'
  'profiles/release-gates.json'
  'scripts/hasp-install-release.sh'
  'scripts/hasp-upgrade-release.sh'
  'scripts/hasp-uninstall-release.sh'
  'scripts/hasp-verify-release.sh'
  'scripts/generate-supply-chain-artifacts.sh'
  'scripts/render-homebrew-formula.sh'
)
EOF

cat >"$artifact_dir/README.md" <<'EOF'
# HASP packaged release

Included artifacts:

- `bin/hasp`
- `LICENSE`
- `RELEASE_MANIFEST`
- `QUICKSTART.md`
- `OPERATOR_GUIDE.md`
- `PRODUCTION_GUIDE.md`
- `agent-profiles/`
- `profiles/`
- `scripts/`

Day-zero release files next to the tarball:

- `SHA256SUMS`
- `SHA256SUMS.asc`
- `hasp-release-public-key.asc`
- `<artifact>.tar.gz.asc`
- `<artifact>_bin.asc`
- `Formula/hasp.rb`
- `sbom.spdx.json`
- `slsa-provenance.json`
- `CODE_SIGNING_STATUS.json`
- `REPRODUCIBLE_BUILD.json`

Start with:

1. verify the tarball with `./scripts/hasp-verify-release.sh <tarball>`
2. run `./bin/hasp version`
3. read `QUICKSTART.md`
4. read `PRODUCTION_GUIDE.md` if you are testing V1 on a real machine
5. use `./scripts/hasp-upgrade-release.sh` and `./scripts/hasp-uninstall-release.sh` for lifecycle work
EOF

cat >"$artifact_dir/QUICKSTART.md" <<'EOF'
# Quickstart

## Verify and install the release

```bash
./scripts/hasp-verify-release.sh <tarball>
./scripts/hasp-install-release.sh --verify <tarball> <install-dir>
```

The verifier expects these sidecars next to the tarball:

- `SHA256SUMS`
- `SHA256SUMS.asc`
- `hasp-release-public-key.asc`
- `<tarball>.asc`
- `<artifact>_bin.asc`

## Verify the binary

```bash
./bin/hasp version
```

## Initialize

```bash
export HASP_MASTER_PASSWORD='choose-a-strong-password'
./bin/hasp init
```

## Import

```bash
./bin/hasp import .env
./bin/hasp import service-account.json
```

## Support profile bootstrap

```bash
./bin/hasp bootstrap \
  --profile claude-code \
  --project-root /path/to/repo \
  --alias secret_01=API_TOKEN
```

For agents that are not first-class support profiles yet, use the generic broker path in `agent-profiles/generic.md`.

If you already enabled automatic repo adoption and want to enroll several local
git repos at once, use:

```bash
./bin/hasp project adopt --under /path/to/workspaces --preview
./bin/hasp project adopt --under /path/to/workspaces
```

That scans for git-backed project roots, skips non-project directories, and
binds the matching repos using the machine defaults from `hasp setup`.

## Safe command execution

```bash
./bin/hasp run \
  --project-root /path/to/repo \
  --env API_TOKEN=secret_01 \
  --grant-project window \
  --grant-secret session \
  --grant-window 15m \
  -- sh -c 'printf "%s" "$API_TOKEN"'
```

## Convenience materialization

```bash
./bin/hasp write-env \
  --project-root /path/to/repo \
  --output /path/to/repo/.env.local \
  --env API_TOKEN=secret_01 \
  --grant-project window \
  --grant-secret session \
  --grant-convenience window
```

## Upgrade and uninstall

```bash
./scripts/hasp-upgrade-release.sh --verify <new-tarball> <install-dir>
./scripts/hasp-uninstall-release.sh <install-dir>
```

The default uninstall path removes the installed release tree only. It does not remove `HASP_HOME` or repo hooks unless you ask for that explicitly.
EOF

cat >"$artifact_dir/OPERATOR_GUIDE.md" <<'EOF'
# Operator guide

## Environment variables

- `HASP_HOME`
- `HASP_MASTER_PASSWORD`
- `HASP_BACKUP_PASSPHRASE`

## Release trust path

Verify a packaged release before install:

```bash
./scripts/hasp-verify-release.sh <tarball>
./scripts/hasp-install-release.sh --verify <tarball> <install-dir>
```

The packaged installer verifies the signed checksum manifest, the tarball signature, and the packaged binary signature before it stages the install tree.

## Repo guardrails

Bulk-adopt local git repos into HASP-managed project bindings:

```bash
./bin/hasp project adopt --under /path/to/workspaces --preview
./bin/hasp project adopt --under /path/to/workspaces
```

Behavior:

- scans under the given directory for git-backed project roots
- skips non-project directories
- uses machine defaults for hook installation and default capture policy
- does not require background crawling or always-on discovery

Packaged helpers:

- `./scripts/hasp-pre-commit.sh`
- `./scripts/hasp-pre-push.sh`
- `./scripts/hasp-deploy.sh`

Manual repo scan:

```bash
./bin/hasp check-repo --project-root /path/to/repo
```

Audited override:

```bash
./bin/hasp check-repo --project-root /path/to/repo --allow-managed-secrets
HASP_ALLOW_MANAGED_SECRETS=1 ./scripts/hasp-deploy.sh /path/to/repo -- <deploy command...>
```

## Upgrade and uninstall

- `./scripts/hasp-upgrade-release.sh` stages a new release tree and swaps it into the target prefix only after verification succeeds.
- `./scripts/hasp-uninstall-release.sh` removes the release tree only by default.
- `HASP_HOME` stays untouched unless the operator passes an explicit purge flag.
- repo hooks stay untouched unless the operator passes explicit repo paths for cleanup.

## Threat-model limits

- V1 reduces accidental exposure and common local leaks on a normal developer machine.
- V1 does not provide strong same-user local isolation.
- V1 does not defend against malicious same-user local processes.
- shell exports and pasted values remain operator hygiene risks, not a protected boundary.
EOF

production_guide_source="$repo_root/docs/v1-production-guide.md"
if [[ ! -f "$production_guide_source" && -f "$repo_root/docs/install.md" ]]; then
  production_guide_source="$repo_root/docs/install.md"
fi
/bin/cp -f "$production_guide_source" "$artifact_dir/PRODUCTION_GUIDE.md"

/usr/bin/tar -C "$release_root" -czf "$tarball" "$artifact_name"

bash "$repo_root/scripts/hasp-sign-release.sh" "$artifact_dir" "$tarball" >/dev/null
bash "$repo_root/scripts/render-homebrew-formula.sh" "${HASP_RELEASE_URL:-file://$tarball}" "$(release_sha256 "$tarball")" "$formula_path" >/dev/null

for required_path in "$tarball" "$tarball_sig_path" "$binary_sig_path" "$checksum_path" "$checksum_sig_path" "$public_key_path" "$formula_path"; do
  if [[ ! -f "$required_path" ]]; then
    printf 'missing packaged release output: %s\n' "$required_path" >&2
    exit 1
  fi
done

printf '%s\n' "$tarball"
