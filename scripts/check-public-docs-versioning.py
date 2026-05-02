#!/usr/bin/env python3
import json
import os
import re
import sys
import hashlib
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
POLICY = json.loads((SCRIPT_DIR / "public-docs-policy.json").read_text(encoding="utf-8"))
DOC_SOURCE_PATTERN = re.compile(POLICY["doc_source_pattern"])
DOCS_VERSION_ID_PATTERN = re.compile(POLICY["docs_version_id_pattern"])
PUBLIC_DOC_SOURCE_PREFIXES = tuple(POLICY["public_doc_source_prefixes"])
ROUTED_INVENTORY_SOURCE_PREFIXES = tuple(POLICY["routed_inventory_source_prefixes"])
ALLOWED_UNROUTED_DOC_SOURCES = set(POLICY["allowed_unrouted_doc_sources"])


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def repo_root() -> Path:
    return Path(os.environ.get("HASP_ROOT_OVERRIDE", Path.cwd())).resolve()


def normalize_version(value: str) -> str:
    raw = str(value or "").strip()
    version = raw if raw.startswith("v") else f"v{raw}"
    if not DOCS_VERSION_ID_PATTERN.fullmatch(version):
        fail(f"invalid docs version id: {raw}")
    return version


def normalize_source(source: str) -> str:
    raw = str(source or "").strip()
    if not raw or raw.startswith("/") or "\\" in raw:
        fail(f"invalid docs source: {raw}")
    parts = raw.split("/")
    if any(part in ("", ".", "..") for part in parts):
        fail(f"invalid docs source: {raw}")
    if not DOC_SOURCE_PATTERN.fullmatch(raw) or not raw.endswith(".md"):
        fail(f"invalid docs source: {raw}")
    if not raw.startswith(PUBLIC_DOC_SOURCE_PREFIXES):
        fail(f"docs source is outside public docs roots: {raw}")
    return raw


def spec_source(spec: dict) -> str:
    if not isinstance(spec, dict):
        fail("invalid docs spec")
    return normalize_source(spec.get("source", ""))


def comparable_specs(specs: object) -> list[dict]:
    if not isinstance(specs, list):
        fail("invalid docs specs")
    output: list[dict] = []
    for spec in specs:
        spec_source(spec)
        output.append(spec)
    return sorted(output, key=lambda spec: (spec_source(spec), json.dumps(spec, sort_keys=True)))


def source_path(root: Path, source: str) -> Path:
    private_path = root / source
    if private_path.exists():
        return private_path
    if source.startswith("public/"):
        exported_path = root / source.removeprefix("public/")
        if exported_path.exists():
            return exported_path
    return private_path


def markdown_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*.md") if path.is_file())


def public_docs_inventory(root: Path) -> list[str]:
    sources: list[str] = []
    private_public_docs = root / "public" / "docs"
    exported_docs = root / "docs"

    if private_public_docs.exists():
        for path in markdown_files(private_public_docs):
            rel = path.relative_to(private_public_docs).as_posix()
            if rel.startswith("agent-profiles/"):
                continue
            sources.append(normalize_source(f"public/docs/{rel}"))
    elif exported_docs.exists():
        for path in markdown_files(exported_docs):
            rel = path.relative_to(exported_docs).as_posix()
            if rel.startswith("agent-profiles/"):
                continue
            sources.append(normalize_source(f"public/docs/{rel}"))

    agent_profiles = root / "docs" / "agent-profiles"
    for path in markdown_files(agent_profiles):
        sources.append(normalize_source(f"docs/agent-profiles/{path.relative_to(agent_profiles).as_posix()}"))

    return sorted(set(source for source in sources if source not in ALLOWED_UNROUTED_DOC_SOURCES))


def routed_inventory_sources(sources: list[str]) -> list[str]:
    return sorted(
        source
        for source in sources
        if (
            source.startswith(ROUTED_INVENTORY_SOURCE_PREFIXES)
        )
        and source not in ALLOWED_UNROUTED_DOC_SOURCES
    )


def sha256_hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    root = repo_root()
    archive_root = root / "public" / "docs-versions"
    if not archive_root.exists():
        archive_root = root / "docs-versions"
    metadata_path = root / "public" / "docs-metadata.json"
    if not metadata_path.exists():
        metadata_path = root / "docs-metadata.json"
    registry_path = archive_root / "versions.json"
    if not registry_path.exists():
        fail(f"missing docs versions registry: {registry_path.relative_to(root)}")
    if not metadata_path.exists():
        fail(f"missing public docs metadata: {metadata_path.relative_to(root)}")

    public_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if public_metadata.get("schemaVersion") != 1:
        fail("public docs metadata has an unsupported schemaVersion")
    canonical_specs = comparable_specs(public_metadata.get("specs") or [])
    canonical_latest = normalize_version(public_metadata.get("latest", ""))
    canonical_sources = sorted(normalize_source(source) for source in (public_metadata.get("sourceFiles") or []))
    spec_sources_from_metadata = sorted(spec["source"] for spec in canonical_specs)
    if canonical_sources != spec_sources_from_metadata:
        fail("public docs metadata sourceFiles/specs mismatch")
    actual_inventory = public_docs_inventory(root)
    expected_inventory = routed_inventory_sources(canonical_sources)
    if actual_inventory != expected_inventory:
        fail(
            "public docs inventory mismatch: "
            f"actual={actual_inventory} expected={expected_inventory}"
        )
    canonical_updated_label = public_metadata.get("updatedLabel")
    if not isinstance(canonical_updated_label, str) or not canonical_updated_label.strip():
        fail("public docs metadata is missing updatedLabel")

    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    latest_id = normalize_version(registry.get("latest", ""))
    repo_version = normalize_version((root / "VERSION").read_text(encoding="utf-8").strip())
    if latest_id != repo_version:
        fail(f"docs latest {latest_id} does not match VERSION {repo_version}")
    if canonical_latest != latest_id:
        fail(f"public docs metadata latest {canonical_latest} does not match docs latest {latest_id}")

    versions = registry.get("versions") or []
    if not any(normalize_version(entry.get("id", "")) == latest_id for entry in versions):
        fail(f"docs latest {latest_id} is missing from versions list")

    for entry in versions:
        version_id = normalize_version(entry.get("id", ""))
        manifest_path = archive_root / version_id / "manifest.json"
        if not manifest_path.exists():
            fail(f"missing docs manifest: {manifest_path.relative_to(root)}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if normalize_version(manifest.get("version", "")) != version_id:
            fail(f"manifest version mismatch for {version_id}")
        if str(entry.get("version", "")) != str(manifest.get("versionNumber", "")):
            fail(f"registry version number mismatch for {version_id}")
        for field in ("createdAt", "sourceCommit"):
            if (entry.get(field) or None) != (manifest.get(field) or None):
                fail(f"registry {field} mismatch for {version_id}")

        specs = manifest.get("specs") or []
        manifest_specs = comparable_specs(specs)
        spec_sources = sorted(spec["source"] for spec in manifest_specs)
        source_files = sorted(normalize_source(source) for source in (manifest.get("sourceFiles") or []))
        if spec_sources != source_files:
            fail(f"manifest sourceFiles/specs mismatch for {version_id}")
        source_hashes = manifest.get("sourceFileSha256") or {}
        if not isinstance(source_hashes, dict):
            fail(f"manifest sourceFileSha256 is invalid for {version_id}")
        hash_sources = sorted(normalize_source(source) for source in source_hashes)
        if hash_sources != source_files:
            fail(f"manifest sourceFileSha256/sourceFiles mismatch for {version_id}")

        for source in source_files:
            snapshot = archive_root / version_id / source
            if not snapshot.exists():
                fail(f"docs snapshot missing: {version_id}/{source}")
            expected_hash = source_hashes.get(source)
            if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                fail(f"docs snapshot hash is invalid for {version_id}/{source}")
            if sha256_hex(snapshot) != expected_hash:
                fail(f"docs snapshot hash mismatch for {version_id}/{source}")

        if manifest.get("sourceArchiveTransform"):
            if manifest.get("sourceArchiveTransform") != "public-docs-sanitized-v1":
                fail(f"unknown docs archive transform for {version_id}")
            sanitized_hashes = manifest.get("sourceFileSanitizedSha256") or {}
            original_hashes = manifest.get("sourceFileOriginalSha256") or {}
            original_missing = sorted(normalize_source(source) for source in (manifest.get("sourceFileOriginalMissing") or []))
            sanitized_sources = sorted(normalize_source(source) for source in (manifest.get("sourceFilesSanitized") or []))
            if sorted(normalize_source(source) for source in sanitized_hashes) != source_files:
                fail(f"manifest sourceFileSanitizedSha256/sourceFiles mismatch for {version_id}")
            for source in source_files:
                sanitized_hash = sanitized_hashes.get(source)
                if not isinstance(sanitized_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", sanitized_hash):
                    fail(f"docs sanitized hash is invalid for {version_id}/{source}")
                if sanitized_hash != source_hashes.get(source):
                    fail(f"docs sanitized hash must match written snapshot hash for {version_id}/{source}")
            original_sources = sorted(normalize_source(source) for source in original_hashes)
            if sorted(original_sources + original_missing) != source_files:
                fail(f"manifest original hash/missing sources mismatch for {version_id}")
            for source, original_hash in original_hashes.items():
                normalized_source = normalize_source(source)
                if not isinstance(original_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", original_hash):
                    fail(f"docs original hash is invalid for {version_id}/{normalized_source}")
            if any(source not in source_files for source in sanitized_sources):
                fail(f"manifest sourceFilesSanitized has unknown source for {version_id}")
            if not set(sanitized_sources).issubset(set(original_sources)):
                fail(f"manifest sourceFilesSanitized includes sources without original hashes for {version_id}")
            for source in sanitized_sources:
                if original_hashes[source] == sanitized_hashes[source]:
                    fail(f"manifest sourceFilesSanitized listed unchanged source for {version_id}/{source}")

        if version_id != latest_id:
            continue
        if source_files != canonical_sources:
            fail(f"latest docs source files do not match public docs metadata for {version_id}")
        if manifest_specs != canonical_specs:
            fail(f"latest docs manifest specs are stale for {version_id}")
        if manifest.get("updatedLabel") != canonical_updated_label:
            fail(f"latest docs updatedLabel is stale for {version_id}")
        if manifest.get("dirty"):
            fail(f"latest docs manifest {version_id} was generated from a dirty source tree")
        if not manifest.get("sourceCommit"):
            fail(f"latest docs manifest {version_id} is missing sourceCommit")
        for source in source_files:
            current = source_path(root, source)
            if not current.exists():
                fail(f"latest docs source missing: {source}")
            snapshot = archive_root / version_id / source
            if current.read_bytes() != snapshot.read_bytes():
                fail(f"latest docs snapshot is stale for {source}")

    print("Public docs versioning snapshot looks consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
