#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

missing=0

while IFS= read -r -d '' file; do
  python3 - "$repo_root" "$file" <<'PY' || missing=1
import os
import re
import sys

repo_root = os.path.abspath(sys.argv[1])
repo_name = os.path.basename(repo_root)
file = sys.argv[2]


def resolve_target(target):
    if not target.startswith("/"):
        return os.path.normpath(os.path.join(os.path.dirname(file), target))
    if os.path.exists(target):
        return target

    parts = os.path.normpath(target).split(os.sep)
    for idx, part in enumerate(parts):
        if part != repo_name:
            continue
        candidate = os.path.join(repo_root, *parts[idx + 1 :])
        if os.path.exists(candidate):
            return candidate
    return target


with open(file, "r", encoding="utf-8") as fh:
    text = fh.read()

for target in re.findall(r'\]\(([^)]+)\)', text):
    if target.startswith(("http://", "https://", "mailto:", "#")):
        continue
    if ":" in target and not target.startswith("/"):
        continue
    target = target.split("#", 1)[0]
    if not target:
        continue
    path = resolve_target(target)
    if not os.path.exists(path):
        print(f"Missing markdown link target: {file} -> {target}", file=sys.stderr)
        sys.exit(1)
PY
done < <(find docs -type f -name '*.md' -print0)

exit "$missing"
