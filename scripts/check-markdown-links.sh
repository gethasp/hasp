#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

missing=0

while IFS= read -r -d '' file; do
  python3 - "$file" <<'PY' || missing=1
import os
import re
import sys

file = sys.argv[1]
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
    path = target if target.startswith("/") else os.path.normpath(os.path.join(os.path.dirname(file), target))
    if not os.path.exists(path):
        print(f"Missing markdown link target: {file} -> {target}", file=sys.stderr)
        sys.exit(1)
PY
done < <(find docs -type f -name '*.md' -print0)

exit "$missing"
