#!/usr/bin/env python3
import os
import re
import sys
from pathlib import Path


def resolve_target(repo_root: Path, file_path: Path, target: str) -> Path:
    if not target.startswith("/"):
        return (file_path.parent / target).resolve()
    absolute = Path(target)
    if absolute.exists():
        return absolute

    parts = absolute.parts
    repo_name = repo_root.name
    for index, part in enumerate(parts):
        if part != repo_name:
            continue
        candidate = repo_root.joinpath(*parts[index + 1 :])
        if candidate.exists():
            return candidate
    return absolute


def markdown_files(repo_root: Path) -> list[Path]:
    docs_root = repo_root / "docs"
    if not docs_root.exists():
        return []
    return sorted(path for path in docs_root.rglob("*.md") if path.is_file())


def main() -> int:
    repo_root = Path(sys.argv[1] if len(sys.argv) > 1 else os.getcwd()).resolve()
    missing = False
    for file_path in markdown_files(repo_root):
        text = file_path.read_text(encoding="utf-8")
        for raw_target in re.findall(r"\]\(([^)]+)\)", text):
            if raw_target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            if ":" in raw_target and not raw_target.startswith("/"):
                continue
            target = raw_target.split("#", 1)[0]
            if not target:
                continue
            path = resolve_target(repo_root, file_path, target)
            if not path.exists():
                print(f"Missing markdown link target: {file_path} -> {target}", file=sys.stderr)
                missing = True
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
