#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  render-homebrew-formula.sh <artifact-url> <artifact-sha256> [output]
  render-homebrew-formula.sh --metadata <release-metadata.json> [output]

Render the HASP Homebrew tap formula for a released artifact.
EOF
}

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
version="$(cat "$repo_root/VERSION")"

render_formula() {
  local output_path="$1"
  local body="$2"
  mkdir -p "$(dirname "$output_path")"
  {
    cat <<EOF
class Hasp < Formula
  desc "Local-first broker for managed secrets in agent workflows"
  homepage "https://gethasp.com"
  version "${version}"
  license :cannot_represent
EOF
    printf '%b\n' "$body"
    cat <<'EOF'
  def install
    libexec.install "bin"
    bin.install_symlink libexec/"bin/hasp"
    (pkgshare/"agent-profiles").install Dir["agent-profiles/*"]
    (pkgshare/"profiles").install Dir["profiles/*"]
    (pkgshare/"scripts").install Dir["scripts/*"]
    pkgshare.install "README.md", "QUICKSTART.md", "OPERATOR_GUIDE.md", "PRODUCTION_GUIDE.md", "RELEASE_MANIFEST", "LICENSE"
  end

  def caveats
    <<~EOS
      Add #{bin} to PATH if it is not already there.
      Set HASP_HOME and HASP_MASTER_PASSWORD before first use.
      Package docs and helper scripts are installed under: #{pkgshare}
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/hasp version")
  end
end
EOF
  } >"$output_path"
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage >&2
  exit 1
fi

if [[ "$1" == "--metadata" ]]; then
  metadata_path="$2"
  output="${3:-Formula/hasp.rb}"
  if [[ ! -f "$metadata_path" ]]; then
    echo "metadata file not found: $metadata_path" >&2
    exit 1
  fi
  formula_body="$(python3 - "$metadata_path" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)

assets = {(item["os"], item["arch"]): item for item in data["artifacts"]}

required = [
    ("darwin", "arm64"),
    ("darwin", "amd64"),
    ("linux", "arm64"),
    ("linux", "amd64"),
]
for key in required:
    if key not in assets:
        raise SystemExit(f"missing release metadata for {key[0]} {key[1]}")

def stanza(formula_os: str, asset_os: str) -> str:
    return f'''  on_{formula_os} do
    on_arm do
      url "{assets[(asset_os, "arm64")]["url"]}"
      sha256 "{assets[(asset_os, "arm64")]["sha256"]}"
    end
    on_intel do
      url "{assets[(asset_os, "amd64")]["url"]}"
      sha256 "{assets[(asset_os, "amd64")]["sha256"]}"
    end
  end'''

print(stanza("macos", "darwin"))
print(stanza("linux", "linux"))
PY
)"
  render_formula "$output" "$formula_body"
  exit 0
fi

artifact_url="$1"
artifact_sha="$2"
output="${3:-Formula/hasp.rb}"

render_formula "$output" "  url \"${artifact_url}\"\n  sha256 \"${artifact_sha}\""
