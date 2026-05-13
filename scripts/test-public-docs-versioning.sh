#!/usr/bin/env bash
set -euo pipefail

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${HASP_TEST_ROOT:-}" ]]; then
  ROOT="$(cd "$HASP_TEST_ROOT" && pwd)"
elif [[ -f "$script_root/VERSION" && -f "$script_root/apps/server/go.mod" && ! -f "$script_root/scripts/export-public-hasp.py" ]]; then
  ROOT="$script_root"
elif ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  :
else
  ROOT="$script_root"
fi

CHECKER="$ROOT/scripts/check-public-docs-versioning.py"
tmp_dir="$(mktemp -d)"
cleanup() {
  /bin/rm -rf "$tmp_dir"
}
trap cleanup EXIT

source_file() {
  local private_path="$1"
  local exported_path="$2"
  if [[ -f "$ROOT/$private_path" ]]; then
    printf '%s\n' "$ROOT/$private_path"
    return 0
  fi
  printf '%s\n' "$ROOT/$exported_path"
}

source_dir() {
  local private_path="$1"
  local exported_path="$2"
  if [[ -d "$ROOT/$private_path" ]]; then
    printf '%s\n' "$ROOT/$private_path"
    return 0
  fi
  printf '%s\n' "$ROOT/$exported_path"
}

copy_public_docs_tree() {
  local dest="$1"
  local source
  source="$(source_dir public/docs docs)"
  /bin/mkdir -p "$dest"
  if [[ ! -d "$ROOT/public/docs" && "$source" == "$ROOT/docs" ]]; then
    while IFS= read -r path; do
      local rel="${path#"$source/"}"
      [[ "$rel" == agent-profiles/* ]] && continue
      /bin/mkdir -p "$dest/$(dirname "$rel")"
      /bin/cp -f "$path" "$dest/$rel"
    done < <(find "$source" -type f -name '*.md' | sort)
    return 0
  fi
  /bin/cp -R "$source/." "$dest"
}

seed_release_tag() {
  local dest="$1"
  local version
  version="$(tr -d '[:space:]' < "$dest/VERSION")"
  git -C "$dest" init -q
  git -C "$dest" config user.email test@example.invalid
  git -C "$dest" config user.name "Docs Versioning Test"
  git -C "$dest" add .
  git -C "$dest" commit -qm "fixture"
  git -C "$dest" tag -a "v$version" -m "fixture v$version"
}

copy_private_shape() {
  local dest="$1"
  /bin/mkdir -p "$dest/public" "$dest/docs"
  /bin/cp -f "$ROOT/VERSION" "$dest/VERSION"
  /bin/cp -R "$(source_dir public/docs-versions docs-versions)" "$dest/public/docs-versions"
  /bin/cp -f "$(source_file public/docs-metadata.json docs-metadata.json)" "$dest/public/docs-metadata.json"
  /bin/cp -f "$(source_file public/README.md README.md)" "$dest/public/README.md"
  /bin/cp -f "$(source_file public/QUICKSTART.md QUICKSTART.md)" "$dest/public/QUICKSTART.md"
  /bin/cp -f "$(source_file public/CHANGELOG.md CHANGELOG.md)" "$dest/public/CHANGELOG.md"
  copy_public_docs_tree "$dest/public/docs"
  /bin/cp -R "$(source_dir docs/agent-profiles docs/agent-profiles)" "$dest/docs/agent-profiles"
  seed_release_tag "$dest"
}

copy_exported_shape() {
  local dest="$1"
  /bin/mkdir -p "$dest/docs"
  /bin/cp -f "$ROOT/VERSION" "$dest/VERSION"
  /bin/cp -R "$(source_dir public/docs-versions docs-versions)" "$dest/docs-versions"
  /bin/cp -f "$(source_file public/docs-metadata.json docs-metadata.json)" "$dest/docs-metadata.json"
  /bin/cp -f "$(source_file public/README.md README.md)" "$dest/README.md"
  /bin/cp -f "$(source_file public/QUICKSTART.md QUICKSTART.md)" "$dest/QUICKSTART.md"
  /bin/cp -f "$(source_file public/CHANGELOG.md CHANGELOG.md)" "$dest/CHANGELOG.md"
  copy_public_docs_tree "$dest/docs"
  /bin/mkdir -p "$dest/docs/agent-profiles"
  /bin/cp -R "$(source_dir docs/agent-profiles docs/agent-profiles)/." "$dest/docs/agent-profiles"
  seed_release_tag "$dest"
}

assert_ok() {
  local root="$1"
  HASP_ROOT_OVERRIDE="$root" python3 "$CHECKER" >/dev/null
}

assert_fails() {
  local label="$1"
  local root="$2"
  if HASP_ROOT_OVERRIDE="$root" python3 "$CHECKER" >/dev/null 2>&1; then
    printf 'expected public docs versioning failure: %s\n' "$label" >&2
    exit 1
  fi
}

mutate_json() {
  local path="$1"
  local expression="$2"
  python3 - "$path" "$expression" <<'PY'
import json
import sys

path, expression = sys.argv[1:3]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
exec(expression, {"data": data})
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2)
    handle.write("\n")
PY
}

private_root="$tmp_dir/private"
copy_private_shape "$private_root"
latest="$(python3 - "$private_root/public/docs-versions/versions.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["latest"])
PY
)"
latest_manifest="$private_root/public/docs-versions/$latest/manifest.json"
historical="$(python3 - "$private_root/public/docs-versions/versions.json" "$latest" <<'PY'
import json
import sys

registry = json.load(open(sys.argv[1], encoding="utf-8"))
latest = sys.argv[2]
for entry in registry["versions"]:
    if entry["id"] != latest:
        print(entry["id"])
        break
PY
)"
if [[ -n "$historical" ]]; then
  historical_source="$(python3 - "$private_root/public/docs-versions/$historical/manifest.json" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
print(manifest["sourceFiles"][0])
PY
)"
fi
assert_ok "$private_root"

if [[ -n "$historical" ]]; then
  missing_historical_root="$tmp_dir/missing-historical-snapshot"
  copy_private_shape "$missing_historical_root"
  /bin/rm -f "$missing_historical_root/public/docs-versions/$historical/$historical_source"
  assert_fails "missing historical snapshot source" "$missing_historical_root"

  corrupt_historical_root="$tmp_dir/corrupt-historical-snapshot"
  copy_private_shape "$corrupt_historical_root"
  printf '\ncorrupt historical snapshot\n' >>"$corrupt_historical_root/public/docs-versions/$historical/$historical_source"
  assert_fails "corrupt historical snapshot source" "$corrupt_historical_root"
fi

dirty_root="$tmp_dir/dirty"
copy_private_shape "$dirty_root"
mutate_json "$dirty_root/public/docs-versions/$latest/manifest.json" 'data["dirty"] = True'
assert_fails "dirty latest manifest" "$dirty_root"

stale_root="$tmp_dir/stale"
copy_private_shape "$stale_root"
printf '\nstale\n' >>"$stale_root/public/README.md"
assert_fails "stale latest snapshot" "$stale_root"

registry_root="$tmp_dir/registry"
copy_private_shape "$registry_root"
mutate_json "$registry_root/public/docs-versions/versions.json" 'data["versions"][0]["createdAt"] = "2000-01-01T00:00:00.000Z"'
assert_fails "registry manifest mismatch" "$registry_root"

source_root="$tmp_dir/source"
copy_private_shape "$source_root"
mutate_json "$source_root/public/docs-versions/$latest/manifest.json" 'data["specs"][0]["source"] = "public/README.md;bad"; data["sourceFiles"][0] = "public/README.md;bad"'
assert_fails "invalid source path" "$source_root"

updated_root="$tmp_dir/updated-label"
copy_private_shape "$updated_root"
mutate_json "$updated_root/public/docs-versions/$latest/manifest.json" 'data["updatedLabel"] = "Stale Month 2026"'
assert_fails "stale updated label" "$updated_root"

title_root="$tmp_dir/title"
copy_private_shape "$title_root"
mutate_json "$title_root/public/docs-versions/$latest/manifest.json" 'data["specs"][0]["title"] = data["specs"][0]["title"] + " stale"'
assert_fails "stale spec title" "$title_root"

order_root="$tmp_dir/order"
copy_private_shape "$order_root"
mutate_json "$order_root/public/docs-versions/$latest/manifest.json" 'data["specs"][0]["order"] = data["specs"][0]["order"] + 1'
assert_fails "stale spec order" "$order_root"

pre_root="$tmp_dir/prerelease"
copy_private_shape "$pre_root"
pre_version="v1.0.0-rc1"
/bin/cp -R "$pre_root/public/docs-versions/$latest" "$pre_root/public/docs-versions/$pre_version"
printf '%s\n' "${pre_version#v}" >"$pre_root/VERSION"
mutate_json "$pre_root/public/docs-versions/versions.json" "data['latest'] = '$pre_version'; data['versions'][0]['id'] = '$pre_version'; data['versions'][0]['label'] = '$pre_version'; data['versions'][0]['version'] = '${pre_version#v}'; data['versions'][0]['path'] = '/docs/$pre_version/'; data['versions'][0]['snapshot'] = '$pre_version/manifest.json'"
mutate_json "$pre_root/public/docs-versions/$pre_version/manifest.json" "data['version'] = '$pre_version'; data['versionNumber'] = '${pre_version#v}'"
mutate_json "$pre_root/public/docs-metadata.json" "data['latest'] = '$pre_version'"
assert_fails "unreleased app docs version" "$pre_root"

metadata_latest_root="$tmp_dir/metadata-latest"
copy_private_shape "$metadata_latest_root"
mutate_json "$metadata_latest_root/public/docs-metadata.json" 'data["latest"] = "v0.0.1"'
assert_fails "metadata latest mismatch" "$metadata_latest_root"

metadata_sources_root="$tmp_dir/metadata-sources"
copy_private_shape "$metadata_sources_root"
mutate_json "$metadata_sources_root/public/docs-metadata.json" 'data["sourceFiles"][0] = "public/README.md;bad"'
assert_fails "metadata sourceFiles mismatch" "$metadata_sources_root"

orphan_root="$tmp_dir/orphan"
copy_private_shape "$orphan_root"
printf '# Orphan fixture\n' >"$orphan_root/public/docs/orphan-fixture.md"
assert_fails "private shape orphan public doc" "$orphan_root"

exported_root="$tmp_dir/exported"
copy_exported_shape "$exported_root"
assert_ok "$exported_root"
printf '# Orphan fixture\n' >"$exported_root/docs/orphan-fixture.md"
assert_fails "exported shape orphan public doc" "$exported_root"
/bin/rm -f "$exported_root/docs/orphan-fixture.md"
printf '\nstale\n' >>"$exported_root/README.md"
assert_fails "exported root stale latest snapshot" "$exported_root"

test -n "$latest_manifest"
printf 'public docs versioning checks passed\n'
