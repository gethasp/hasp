#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: generate-supply-chain-artifacts.sh <artifact-dir>

Generate V1 release supply-chain target artifacts for a packaged HASP release.
EOF
}

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 1
fi

artifact_dir="$1"
binary="$artifact_dir/bin/hasp"
if [[ ! -x "$binary" ]]; then
  echo "release binary not found: $binary" >&2
  exit 1
fi

target_os="${HASP_TARGET_OS:-$(go env GOOS)}"
target_arch="${HASP_TARGET_ARCH:-$(go env GOARCH)}"
host_os="$(go env GOHOSTOS)"
host_arch="$(go env GOHOSTARCH)"
version=""
if [[ "$target_os" == "$host_os" && "$target_arch" == "$host_arch" ]]; then
  version="$("$binary" version 2>/dev/null || true)"
fi
if [[ -z "$version" ]]; then
  version="$(< VERSION)"
fi
binary_sha256="$(shasum -a 256 "$binary" | awk '{print $1}')"
go_version="$(go version | sed 's/"/\\"/g')"
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

{
  printf '{\n'
  printf '  "spdxVersion": "SPDX-2.3",\n'
  printf '  "dataLicense": "CC0-1.0",\n'
  printf '  "SPDXID": "SPDXRef-DOCUMENT",\n'
  printf '  "name": "hasp-%s",\n' "$version"
  printf '  "documentNamespace": "https://gethasp.example.invalid/spdx/hasp-%s-%s",\n' "$version" "$binary_sha256"
  printf '  "creationInfo": {\n'
  printf '    "created": "%s",\n' "$generated_at"
  printf '    "creators": ["Tool: hasp generate-supply-chain-artifacts"]\n'
  printf '  },\n'
  printf '  "packages": [\n'
  printf '    {\n'
  printf '      "name": "hasp",\n'
  printf '      "SPDXID": "SPDXRef-Package-hasp",\n'
  printf '      "versionInfo": "%s",\n' "$version"
  printf '      "downloadLocation": "NOASSERTION",\n'
  printf '      "filesAnalyzed": false,\n'
  printf '      "checksums": [{"algorithm": "SHA256", "checksumValue": "%s"}],\n' "$binary_sha256"
  printf '      "supplier": "Organization: HASP"\n'
  printf '    }\n'
  printf '  ]\n'
  printf '}\n'
} >"$artifact_dir/sbom.spdx.json"

{
  printf '{\n'
  printf '  "_type": "https://in-toto.io/Statement/v1",\n'
  printf '  "predicateType": "https://slsa.dev/provenance/v1",\n'
  printf '  "subject": [\n'
  printf '    {\n'
  printf '      "name": "bin/hasp",\n'
  printf '      "digest": {"sha256": "%s"}\n' "$binary_sha256"
  printf '    }\n'
  printf '  ],\n'
  printf '  "predicate": {\n'
  printf '    "buildDefinition": {\n'
  printf '      "buildType": "https://gethasp.example.invalid/build/go",\n'
  printf '      "externalParameters": {\n'
  printf '        "version": "%s",\n' "$version"
  printf '        "target_os": "%s",\n' "$target_os"
  printf '        "target_arch": "%s"\n' "$target_arch"
  printf '      },\n'
  printf '      "internalParameters": {}\n'
  printf '    },\n'
  printf '    "runDetails": {\n'
  printf '      "builder": {"id": "hasp-local-release-scripts"},\n'
  printf '      "metadata": {\n'
  printf '        "invocationId": "%s",\n' "$binary_sha256"
  printf '        "startedOn": "%s",\n' "$generated_at"
  printf '        "finishedOn": "%s"\n' "$generated_at"
  printf '      },\n'
  printf '      "byproducts": [\n'
  printf '        {"name": "go_version", "value": "%s"}\n' "$go_version"
  printf '      ]\n'
  printf '    }\n'
  printf '  }\n'
  printf '}\n'
} >"$artifact_dir/slsa-provenance.json"

codesign_status="unsupported"
codesign_detail="macOS code signing verification is available only on darwin with codesign"
if [[ "$target_os" == "darwin" && "$(uname -s)" == "Darwin" ]] && command -v codesign >/dev/null 2>&1; then
  if codesign --verify --deep --strict "$binary" >/dev/null 2>&1; then
    codesign_status="verified"
    codesign_detail="codesign verification passed"
  else
    codesign_status="unsigned"
    codesign_detail="codesign verification did not find a valid macOS signature"
  fi
fi
{
  printf '{\n'
  printf '  "status": "%s",\n' "$codesign_status"
  printf '  "detail": "%s",\n' "$codesign_detail"
  printf '  "binary_sha256": "%s",\n' "$binary_sha256"
  printf '  "generated_at": "%s"\n' "$generated_at"
  printf '}\n'
} >"$artifact_dir/CODE_SIGNING_STATUS.json"

repro_status="not_run"
repro_detail="set HASP_RUN_REPRODUCIBLE_BUILD_CHECK=1 to run the slower reproducible build comparison during packaging"
if [[ "${HASP_RUN_REPRODUCIBLE_BUILD_CHECK:-0}" == "1" ]]; then
  temp_binary="$(mktemp)"
  if bash ./scripts/reproducible-build.sh -o "$temp_binary" --pkg ./apps/server/cmd/hasp >/dev/null 2>&1; then
    repro_sha256="$(shasum -a 256 "$temp_binary" | awk '{print $1}')"
    if [[ "$repro_sha256" == "$binary_sha256" ]]; then
      repro_status="verified"
      repro_detail="reproducible build hash matched packaged binary"
    else
      repro_status="mismatch"
      repro_detail="reproducible build hash did not match packaged binary"
    fi
  else
    repro_status="failed"
    repro_detail="reproducible build command failed"
  fi
  /bin/rm -f "$temp_binary"
fi
{
  printf '{\n'
  printf '  "status": "%s",\n' "$repro_status"
  printf '  "detail": "%s",\n' "$repro_detail"
  printf '  "binary_sha256": "%s",\n' "$binary_sha256"
  printf '  "generated_at": "%s"\n' "$generated_at"
  printf '}\n'
} >"$artifact_dir/REPRODUCIBLE_BUILD.json"

printf '%s\n' "$artifact_dir/sbom.spdx.json"
printf '%s\n' "$artifact_dir/slsa-provenance.json"
printf '%s\n' "$artifact_dir/CODE_SIGNING_STATUS.json"
printf '%s\n' "$artifact_dir/REPRODUCIBLE_BUILD.json"
