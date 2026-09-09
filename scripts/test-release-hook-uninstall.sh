#!/usr/bin/env bash
set -euo pipefail

ROOT="${HASP_TEST_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
tmp_dir="$(mktemp -d)"
trap '/bin/rm -rf "$tmp_dir"' EXIT

fixture() {
  install_dir="$tmp_dir/$1/install"
  repo_dir="$tmp_dir/$1/repo"
  mkdir -p "$install_dir/scripts" "$repo_dir"
  touch "$install_dir/RELEASE_MANIFEST"
  cp "$ROOT/scripts/hasp-install-hooks.sh" "$install_dir/scripts/"
  git -C "$repo_dir" init -q
  git -C "$repo_dir" config core.hooksPath .git/hooks
  hooks_dir="$repo_dir/.git/hooks"
}

install_hooks() {
  (cd "$repo_dir" && "$BASH" "$install_dir/scripts/hasp-install-hooks.sh") >/dev/null
}

uninstall() {
  "$BASH" "$ROOT/scripts/hasp-uninstall-release.sh" --remove-hooks-from "$repo_dir" "$install_dir"
}

assert_removed() {
  if [[ -e "$1" || -L "$1" ]]; then
    printf 'uninstall left path behind: %s\n' "$1" >&2
    exit 1
  fi
}

# shellcheck disable=SC2016
for name in plain "spaces and [patterns].*" "single'quote" 'literal$(command)' $'line\nbreak'; do
  fixture "$name"
  install_hooks
  uninstall
  assert_removed "$hooks_dir/pre-commit"
  assert_removed "$hooks_dir/pre-push"
  assert_removed "$install_dir"
done

fixture missing-hooks
git -C "$repo_dir" config core.hooksPath .hooks/nested
hooks_dir="$repo_dir/.hooks/nested"
install_hooks
uninstall
assert_removed "$hooks_dir/pre-commit"
assert_removed "$hooks_dir/pre-push"

fixture no-hooks
"$BASH" "$ROOT/scripts/hasp-uninstall-release.sh" "$install_dir"
assert_removed "$install_dir"

fixture saved
for hook_name in pre-commit pre-push; do
  printf '#!/usr/bin/env bash\nprintf "saved %s\\n"\n' "$hook_name" >"$hooks_dir/$hook_name"
  chmod +x "$hooks_dir/$hook_name"
  cp -p "$hooks_dir/$hook_name" "$tmp_dir/$hook_name.original"
done
install_hooks
uninstall
for hook_name in pre-commit pre-push; do
  cmp "$tmp_dir/$hook_name.original" "$hooks_dir/$hook_name"
  test -x "$hooks_dir/$hook_name"
  assert_removed "$hooks_dir/$hook_name.pre-hasp"
done

fixture legacy
for hook_name in pre-commit pre-push; do
  printf '#!/usr/bin/env bash\n# HASP-MANAGED-HOOK\nexport HASP_ROOT_OVERRIDE="%s"\n' "$install_dir" >"$hooks_dir/$hook_name"
done
uninstall
assert_removed "$hooks_dir/pre-commit"
assert_removed "$hooks_dir/pre-push"

fixture unrelated
printf '#!/usr/bin/env bash\n# HASP-MANAGED-HOOK\nexport HASP_ROOT_OVERRIDE=%q\n' "$install_dir-other" >"$hooks_dir/pre-commit"
printf '#!/usr/bin/env bash\nexport HASP_ROOT_OVERRIDE=%q\n' "$install_dir" >"$hooks_dir/pre-push"
cp "$hooks_dir/pre-commit" "$tmp_dir/unrelated-commit"
cp "$hooks_dir/pre-push" "$tmp_dir/unrelated-push"
uninstall
cmp "$tmp_dir/unrelated-commit" "$hooks_dir/pre-commit"
cmp "$tmp_dir/unrelated-push" "$hooks_dir/pre-push"

fixture symlink-backup
install_hooks
printf 'original\n' >"$tmp_dir/symlink-target"
ln -s "$tmp_dir/symlink-target" "$hooks_dir/pre-commit.pre-hasp"
if uninstall >"$tmp_dir/symlink-error" 2>&1; then
  printf 'uninstall accepted a symlink hook backup\n' >&2
  exit 1
fi
test -d "$install_dir"
test -f "$hooks_dir/pre-commit"
grep -Fq 'original' "$tmp_dir/symlink-target"
grep -Fq 'refusing to restore' "$tmp_dir/symlink-error"

printf 'release hook uninstall checks passed\n'
