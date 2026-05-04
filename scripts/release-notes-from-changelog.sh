#!/usr/bin/env bash
set -euo pipefail

tag="${1:-}"
if [[ -z "$tag" ]]; then
  echo "usage: release-notes-from-changelog.sh <tag>" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
changelog="$repo_root/CHANGELOG.md"
if [[ ! -f "$changelog" && -f "$repo_root/public/CHANGELOG.md" ]]; then
  changelog="$repo_root/public/CHANGELOG.md"
fi
if [[ ! -f "$changelog" ]]; then
  echo "missing CHANGELOG.md" >&2
  exit 1
fi

python3 - "$changelog" "$tag" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
tag = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines()
capture = False
captured = []

for line in lines:
    if line.startswith("## "):
        if capture:
            break
        if line.startswith(f"## [{tag}]"):
            capture = True
            captured.append(line)
        continue
    if capture:
        captured.append(line)

if not captured:
    raise SystemExit(f"missing changelog section for {tag}")

print("\n".join(captured).strip() + "\n")
PY
