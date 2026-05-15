#!/usr/bin/env python3
import json
import os
import re
import sys
from pathlib import Path


def repo_root() -> Path:
    if os.environ.get("HASP_TEST_ROOT"):
        return Path(os.environ["HASP_TEST_ROOT"]).resolve()
    script_root = Path(__file__).resolve().parent.parent
    return script_root


def load_contract(root: Path) -> dict:
    path = root / "scripts" / "public-release-contract.json"
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def fail(message: str) -> None:
    raise SystemExit(message)


def read_text(path: Path) -> str:
    if not path.exists():
        fail(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def make_target(text: str, name: str) -> tuple[list[str], list[str]]:
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if not line.startswith(name + ":"):
            continue
        _, _, dep_text = line.partition(":")
        deps = dep_text.split()
        recipe: list[str] = []
        for next_line in lines[idx + 1 :]:
            if not next_line:
                continue
            if not next_line.startswith("\t"):
                break
            recipe.append(next_line.strip().removeprefix("@"))
        return deps, recipe
    fail(f"Makefile target {name!r} not found")


def require_contains_all(label: str, haystack: str, needles: list[str]) -> None:
    for needle in needles:
        if needle not in haystack:
            fail(f"{label} missing required content: {needle}")


def require_in_order(label: str, haystack: str, needles: list[str]) -> None:
    position = -1
    for needle in needles:
        next_position = haystack.find(needle, position + 1)
        if next_position < 0:
            fail(f"{label} missing required ordered content: {needle}")
        position = next_position


def validate_makefile(path: Path, spec: dict) -> None:
    text = read_text(path)
    for target, rules in spec.items():
        deps, recipe = make_target(text, target)
        label = f"{path}:{target}"
        if "deps_include" in rules:
            missing = [dep for dep in rules["deps_include"] if dep not in deps]
            if missing:
                fail(f"{label} missing dependencies: {', '.join(missing)}")
        if "deps_exact" in rules and deps != rules["deps_exact"]:
            fail(f"{label} dependencies = {deps}, want {rules['deps_exact']}")
        if "recipe_in_order" in rules:
            require_in_order(label, "\n".join(recipe), rules["recipe_in_order"])


def workflow_job_block(text: str, job: str) -> str:
    pattern = re.compile(rf"^  {re.escape(job)}:\n(?P<body>(?:    .*\n|[ \t]*\n)*)", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        fail(f"workflow job {job!r} not found")
    return match.group(0)


def workflow_job_needs(block: str) -> list[str]:
    inline = re.search(r"^\s{4}needs:\s*([A-Za-z0-9_-]+)\s*$", block, re.MULTILINE)
    if inline:
        return [inline.group(1)]
    needs_match = re.search(r"^\s{4}needs:\s*\n(?P<body>(?:\s{6}- .+\n)+)", block, re.MULTILINE)
    if not needs_match:
        return []
    return [line.strip()[2:].strip() for line in needs_match.group("body").splitlines()]


def validate_workflow(path: Path, spec: dict) -> None:
    text = read_text(path)
    for forbidden in spec.get("forbid_contains", []):
        if forbidden in text:
            fail(f"{path} contains forbidden content: {forbidden}")
    for job, rules in spec.get("jobs", {}).items():
        block = workflow_job_block(text, job)
        label = f"{path}:{job}"
        if "needs_include" in rules:
            needs = workflow_job_needs(block)
            missing = [need for need in rules["needs_include"] if need not in needs]
            if missing:
                fail(f"{label} missing needs: {', '.join(missing)}")
        if "runs_on_contains" in rules:
            require_contains_all(label, block, [f"runs-on: {rules['runs_on_contains']}"])
        if "run_contains" in rules:
            require_contains_all(label, block, rules["run_contains"])
        if "env_contains" in rules:
            require_contains_all(label, block, rules["env_contains"])
    if "step_names_in_order" in spec:
        require_in_order(str(path), text, spec["step_names_in_order"])


def public_workflow_path(root: Path, rel: str) -> Path:
    private_public_path = root / "public" / rel
    if private_public_path.exists():
        return private_public_path
    return root / rel


def validate_script_commands(root: Path, spec: dict) -> None:
    for rel, rules in spec.items():
        path = root / rel
        commands = []
        for raw in read_text(path).splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line in {"set -euo pipefail"}:
                continue
            commands.append(line)
        if "commands_in_order" in rules:
            require_in_order(str(path), "\n".join(commands), rules["commands_in_order"])


def validate_files(root: Path, spec: dict) -> None:
    for rel, rules in spec.items():
        path = root / rel
        text = read_text(path)
        if "contains" in rules:
            require_contains_all(str(path), text, rules["contains"])


def main() -> int:
    root = repo_root()
    contract = load_contract(root)
    public_root = root / "public" if (root / "public" / "Makefile").exists() else root

    if (root / "scripts" / "check-public-export.sh").exists():
        if "private_makefile_targets" in contract:
            validate_makefile(root / "Makefile", contract["private_makefile_targets"])
        private_verify = contract["workflows"].get("private_verify")
        if private_verify:
            validate_workflow(root / private_verify["path"], private_verify)

    validate_makefile(public_root / "Makefile", contract["public_makefile_targets"])
    validate_script_commands(public_root, contract["scripts"])
    validate_files(public_root, contract.get("files", {}))
    validate_workflow(public_workflow_path(root, contract["workflows"]["public_ci"]["path"]), contract["workflows"]["public_ci"])
    validate_workflow(public_workflow_path(root, contract["workflows"]["public_release"]["path"]), contract["workflows"]["public_release"])
    print("public release contract checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
