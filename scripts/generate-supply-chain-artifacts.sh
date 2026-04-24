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

version="$("$binary" version 2>/dev/null || true)"
if [[ -z "$version" ]]; then
  version="$(< VERSION)"
fi
binary_sha256="$(shasum -a 256 "$binary" | awk '{print $1}')"
go_version="$(go version | sed 's/"/\\"/g')"
target_os="${HASP_TARGET_OS:-$(go env GOOS)}"
target_arch="${HASP_TARGET_ARCH:-$(go env GOARCH)}"
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat >"$artifact_dir/sbom.spdx.json" <<EOF
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "hasp-$version",
  "documentNamespace": "https://gethasp.example.invalid/spdx/hasp-$version-$binary_sha256",
  "creationInfo": {
    "created": "$generated_at",
    "creators": ["Tool: hasp generate-supply-chain-artifacts"]
  },
  "packages": [
    {
      "name": "hasp",
      "SPDXID": "SPDXRef-Package-hasp",
      "versionInfo": "$version",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "checksums": [{"algorithm": "SHA256", "checksumValue": "$binary_sha256"}],
      "supplier": "Organization: HASP"
    }
  ]
}
EOF

cat >"$artifact_dir/slsa-provenance.json" <<EOF
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [
    {
      "name": "bin/hasp",
      "digest": {"sha256": "$binary_sha256"}
    }
  ],
  "predicate": {
    "buildDefinition": {
      "buildType": "https://gethasp.example.invalid/build/go",
      "externalParameters": {
        "version": "$version",
        "target_os": "$target_os",
        "target_arch": "$target_arch"
      },
      "internalParameters": {}
    },
    "runDetails": {
      "builder": {"id": "hasp-local-release-scripts"},
      "metadata": {
        "invocationId": "$binary_sha256",
        "startedOn": "$generated_at",
        "finishedOn": "$generated_at"
      },
      "byproducts": [
        {"name": "go_version", "value": "$go_version"}
      ]
    }
  }
}
EOF

codesign_status="unsupported"
codesign_detail="macOS code signing verification is available only on darwin with codesign"
if [[ "$(uname -s)" == "Darwin" ]] && command -v codesign >/dev/null 2>&1; then
  if codesign --verify --deep --strict "$binary" >/dev/null 2>&1; then
    codesign_status="verified"
    codesign_detail="codesign verification passed"
  else
    codesign_status="unsigned"
    codesign_detail="codesign verification did not find a valid macOS signature"
  fi
fi
cat >"$artifact_dir/CODE_SIGNING_STATUS.json" <<EOF
{
  "status": "$codesign_status",
  "detail": "$codesign_detail",
  "binary_sha256": "$binary_sha256",
  "generated_at": "$generated_at"
}
EOF

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
cat >"$artifact_dir/REPRODUCIBLE_BUILD.json" <<EOF
{
  "status": "$repro_status",
  "detail": "$repro_detail",
  "binary_sha256": "$binary_sha256",
  "generated_at": "$generated_at"
}
EOF

printf '%s\n' "$artifact_dir/sbom.spdx.json"
printf '%s\n' "$artifact_dir/slsa-provenance.json"
printf '%s\n' "$artifact_dir/CODE_SIGNING_STATUS.json"
printf '%s\n' "$artifact_dir/REPRODUCIBLE_BUILD.json"
