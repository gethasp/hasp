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
unsigned="${HASP_PACKAGE_RELEASE_UNSIGNED:-0}"
release_build_date="${HASP_BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

case "$unsigned" in
  0|1) ;;
  *)
    printf 'HASP_PACKAGE_RELEASE_UNSIGNED must be 0 or 1\n' >&2
    exit 2
    ;;
esac
export HASP_BUILD_DATE="$release_build_date"

verify_upgrade_trust_roots() {
  if [[ "${HASP_ALLOW_MISSING_UPGRADE_TRUST_ROOTS:-0}" == "1" ]]; then
    return 0
  fi

  local binary="$artifact_dir/bin/hasp"
  local host_os host_arch
  host_os="$(go env GOHOSTOS)"
  host_arch="$(go env GOHOSTARCH)"
  if [[ "$os_name" == "$host_os" && "$arch_name" == "$host_arch" ]]; then
    if ! "$binary" version --json | grep -q '"upgrade_trust_roots":true'; then
      printf 'packaged binary reports upgrade_trust_roots=false; refusing release artifact\n' >&2
      exit 1
    fi
    return 0
  fi

  if ! command -v strings >/dev/null 2>&1; then
    printf 'strings is required to verify cross-built upgrade trust roots for %s/%s\n' "$os_name" "$arch_name" >&2
    exit 1
  fi
  if ! strings -a "$binary" | awk -v needle="$HASP_UPGRADE_TRUST_ROOTS_HEX" 'index($0, needle) { found = 1 } END { exit found ? 0 : 1 }'; then
    printf 'packaged cross-built binary does not contain HASP_UPGRADE_TRUST_ROOTS_HEX; refusing release artifact\n' >&2
    exit 1
  fi
}

if [[ -z "${HASP_UPGRADE_TRUST_ROOTS_HEX:-}" && "${HASP_ALLOW_MISSING_UPGRADE_TRUST_ROOTS:-0}" != "1" ]]; then
  printf 'missing HASP_UPGRADE_TRUST_ROOTS_HEX; release binaries must embed hasp upgrade trust roots (set HASP_ALLOW_MISSING_UPGRADE_TRUST_ROOTS=1 only for explicit dev packaging)\n' >&2
  exit 1
fi

/bin/rm -rf "$artifact_dir" "$tarball" "$checksum_path" "$checksum_sig_path" "$public_key_path" "$tarball_sig_path" "$binary_sig_path" "$fingerprint_path" "$formula_dir"
/bin/mkdir -p "$artifact_dir/bin" "$artifact_dir/agent-profiles" "$artifact_dir/profiles" "$artifact_dir/scripts" "$formula_dir"

bash ./scripts/build.sh -o "$artifact_dir/bin/hasp"
verify_upgrade_trust_roots
/bin/cp -f "$repo_root/LICENSE" "$artifact_dir/LICENSE"
bash ./scripts/generate-supply-chain-artifacts.sh "$artifact_dir" >/dev/null

packaged_scripts=(
  hasp-common.sh
  hasp-release-common.sh
  release-public-key-trust.sh
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

{
  printf '# HASP packaged release\n\n'
  printf 'Included artifacts:\n\n'
  printf -- "- \`%s\`\n" \
    bin/hasp \
    LICENSE \
    RELEASE_MANIFEST \
    QUICKSTART.md \
    OPERATOR_GUIDE.md \
    PRODUCTION_GUIDE.md \
    agent-profiles/ \
    profiles/ \
    scripts/
  printf '\nDay-zero release files next to the tarball:\n\n'
  printf -- "- \`%s\`\n" \
    SHA256SUMS \
    SHA256SUMS.asc \
    hasp-release-public-key.asc \
    '<artifact>.tar.gz.asc' \
    '<artifact>_bin.asc' \
    Formula/hasp.rb \
    sbom.spdx.json \
    slsa-provenance.json \
    CODE_SIGNING_STATUS.json \
    REPRODUCIBLE_BUILD.json
  printf '\nStart with:\n\n'
  printf "1. verify the tarball with \`./scripts/hasp-verify-release.sh <tarball>\`\n"
  printf "2. run \`./bin/hasp version\`\n"
  printf "3. read \`QUICKSTART.md\`\n"
  printf "4. read \`PRODUCTION_GUIDE.md\` if you are testing V1 on a real machine\n"
  printf "5. use \`./scripts/hasp-upgrade-release.sh\` and \`./scripts/hasp-uninstall-release.sh\` for lifecycle work\n"
} >"$artifact_dir/README.md"

copy_first_existing() {
  local dest="$1"
  shift
  local candidate
  for candidate in "$@"; do
    if [[ -f "$candidate" ]]; then
      /bin/cp -f "$candidate" "$dest"
      return 0
    fi
  done
  printf 'missing release documentation source for %s\n' "$dest" >&2
  return 1
}

copy_first_existing "$artifact_dir/QUICKSTART.md" "$repo_root/public/QUICKSTART.md" "$repo_root/QUICKSTART.md"
# shellcheck disable=SC2016
python3 -c '
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace("## 1. Build or download a release", "## 1. Verify or install this packaged release")
text = text.replace(
    "From source:\n\n```bash\nmake build\nbin/hasp version\n```\n\n",
    "",
)
text = text.replace(
    "From a packaged release:\n\n```bash\nscripts/hasp-verify-release.sh dist/release/hasp_<version>_<os>_<arch>.tar.gz\nscripts/hasp-install-release.sh --verify dist/release/hasp_<version>_<os>_<arch>.tar.gz\n```",
    "From the directory containing this tarball and sidecars:\n\n```bash\n./scripts/hasp-verify-release.sh ../hasp_<version>_<os>_<arch>.tar.gz\n./scripts/hasp-install-release.sh --verify ../hasp_<version>_<os>_<arch>.tar.gz\n```",
)
text = text.replace(
    "export HASP_MASTER_PASSWORD='\''choose-a-strong-password'\''\nbin/hasp init",
    "export HASP_MASTER_PASSWORD='\''choose-a-strong-password'\''\n./bin/hasp init",
)
text = re.sub(r"(?<![./])bin/hasp(?=\s)", "./bin/hasp", text)
text = re.sub(r"(?<![./])scripts/(hasp-(?:upgrade|uninstall)-release\.sh)", r"./scripts/\1", text)
path.write_text(text, encoding="utf-8")
' "$artifact_dir/QUICKSTART.md"
copy_first_existing "$artifact_dir/OPERATOR_GUIDE.md" "$repo_root/public/docs/operator-guide.md" "$repo_root/docs/operator-guide.md"

production_guide_source="$repo_root/docs/v1-production-guide.md"
if [[ ! -f "$production_guide_source" && -f "$repo_root/docs/install.md" ]]; then
  production_guide_source="$repo_root/docs/install.md"
fi
/bin/cp -f "$production_guide_source" "$artifact_dir/PRODUCTION_GUIDE.md"

write_release_manifest() {
  local file=""
  local rel=""
  {
    printf "artifact_name_expected='%s'\n" "$artifact_name"
    printf "name='%s'\n" "$artifact_name"
    printf "version='%s'\n" "$version"
    printf "os='%s'\n" "$os_name"
    printf "arch='%s'\n" "$arch_name"
    printf 'release_files=(\n'
    printf "  'RELEASE_MANIFEST'\n"
    while IFS= read -r file; do
      rel="${file#"$artifact_dir"/}"
      [[ "$rel" != "RELEASE_MANIFEST" ]] || continue
      if [[ "$rel" == *"'"* ]] || ! release_validate_manifest_path "$rel"; then
        printf 'unsafe release file path: %s\n' "$rel" >&2
        return 1
      fi
      printf "  '%s'\n" "$rel"
    done < <(find "$artifact_dir" -type f -print | LC_ALL=C sort)
    printf ')\n'
  } >"$artifact_dir/RELEASE_MANIFEST"
}

write_release_manifest
release_tar -C "$release_root" -czf "$tarball" "$artifact_name"

if [[ "$unsigned" == "1" ]]; then
  printf '%s\n' "$tarball"
  exit 0
fi

bash "$repo_root/scripts/hasp-sign-release.sh" "$artifact_dir" "$tarball" >/dev/null
bash "$repo_root/scripts/render-homebrew-formula.sh" "${HASP_RELEASE_URL:-file://$tarball}" "$(release_sha256 "$tarball")" "$formula_path" >/dev/null

for required_path in "$tarball" "$tarball_sig_path" "$binary_sig_path" "$checksum_path" "$checksum_sig_path" "$public_key_path" "$fingerprint_path" "$formula_path"; do
  if [[ ! -f "$required_path" ]]; then
    printf 'missing packaged release output: %s\n' "$required_path" >&2
    exit 1
  fi
done

printf '%s\n' "$tarball"
