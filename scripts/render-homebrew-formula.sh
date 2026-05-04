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

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(cat "$repo_root/VERSION")"

render_formula() {
  local output_path="$1"
  local body="$2"
  mkdir -p "$(dirname "$output_path")"
  {
    printf 'class Hasp < Formula\n'
    printf '  desc "Local-first broker for managed secrets in agent workflows"\n'
    printf '  homepage "https://gethasp.com"\n'
    printf '  version "%s"\n' "$version"
    printf '  license :cannot_represent\n'
    printf '%b\n' "$body"
    printf '  def install\n'
    printf '    libexec.install "bin"\n'
    printf '    bin.install_symlink libexec/"bin/hasp"\n'
    printf '    (pkgshare/"agent-profiles").install Dir["agent-profiles/*"]\n'
    printf '    (pkgshare/"profiles").install Dir["profiles/*"]\n'
    printf '    (pkgshare/"scripts").install Dir["scripts/*"]\n'
    printf '    pkgshare.install "README.md", "QUICKSTART.md", "OPERATOR_GUIDE.md", "PRODUCTION_GUIDE.md", "RELEASE_MANIFEST", "LICENSE"\n'
    printf '  end\n\n'
    printf '  def caveats\n'
    printf '    <<~EOS\n'
    printf '      Add #{bin} to PATH if it is not already there.\n'
    printf '      Set HASP_HOME and HASP_MASTER_PASSWORD before first use.\n'
    printf '      Package docs and helper scripts are installed under: #{pkgshare}\n'
    printf '    EOS\n'
    printf '  end\n\n'
    printf '  test do\n'
    printf '    assert_match version.to_s, shell_output("#{bin}/hasp version")\n'
    printf '  end\n'
    printf 'end\n'
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
  formula_body="$(python3 "$repo_root/scripts/render_homebrew_formula_body.py" "$metadata_path" "$repo_root/scripts/release-targets.json")"
  render_formula "$output" "$formula_body"
  exit 0
fi

artifact_url="$1"
artifact_sha="$2"
output="${3:-Formula/hasp.rb}"

render_formula "$output" "  url \"${artifact_url}\"\n  sha256 \"${artifact_sha}\""
