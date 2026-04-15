#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

make verify-ci
bash ./scripts/release-smoke.sh
make evals
make release-smoke

temp_home="$(mktemp -d)"
trap 'rm -rf "$temp_home"' EXIT
export HASP_HOME="$temp_home"
export HASP_MASTER_PASSWORD="conformance-password"

bash ./scripts/build.sh
./bin/hasp init >/dev/null
repo_dir="$temp_home/repo"
mkdir -p "$repo_dir"
git -C "$repo_dir" init >/dev/null 2>&1
./bin/hasp set --name api_token --value abc123 >/dev/null
./bin/hasp project bind --project-root "$repo_dir" --alias secret_01=api_token >/dev/null
printf 'TOKEN=abc123\n' >"$repo_dir/.env.local"
if scripts/hasp-deploy.sh "$repo_dir" -- true; then
  echo "Conformance failed: deploy wrapper did not block managed secret materialization" >&2
  exit 1
fi
HASP_ALLOW_MANAGED_SECRETS=1 scripts/hasp-deploy.sh "$repo_dir" -- true

request_file="$temp_home/mcp-requests.jsonl"
cat >"$request_file" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"tools/list"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hasp_list","arguments":{"project_root":"REPO_ROOT","grant_project":"window"}}}
EOF

sed -i.bak "s#REPO_ROOT#$repo_dir#g" "$request_file"
rm -f "$request_file.bak"

response="$("./bin/hasp" mcp <"$request_file")"
case "$response" in
  *hasp_list*) ;;
  *)
    echo "MCP conformance failed: expected hasp_list in tools/list response" >&2
    exit 1
    ;;
esac
case "$response" in
  *canonical_root*|*\"binding\"*)
    echo "MCP conformance failed: agent-safe list leaked binding internals" >&2
    exit 1
    ;;
esac

tarball="$(bash ./scripts/package-release.sh)"
artifact_dir="$(mktemp -d)"
trap 'rm -rf "$temp_home" "$artifact_dir"' EXIT
tar -C "$artifact_dir" -xzf "$tarball"
artifact_root="$(find "$artifact_dir" -maxdepth 1 -type d -name 'hasp_*' | head -n 1)"
test -x "$artifact_root/bin/hasp"
test -f "$artifact_root/README.md"
test -f "$artifact_root/QUICKSTART.md"
test -f "$artifact_root/OPERATOR_GUIDE.md"
test -f "$artifact_root/LICENSE"
test -f "$artifact_root/agent-profiles/README.md"
for profile in ./apps/server/profiles/*.json; do
  name="$(basename "$profile" .json)"
  [[ "$name" == "release-gates" ]] && continue
  test -f "$artifact_root/agent-profiles/${name}.md"
done
test -f "$artifact_root/scripts/hasp-deploy.sh"
case "$(cat "$artifact_root/QUICKSTART.md")" in
  *make\ build*|*./hasp\ version*)
    echo "Packaged quickstart is not artifact-specific" >&2
    exit 1
    ;;
esac
HASP_HOME="$(mktemp -d)" HASP_MASTER_PASSWORD="artifact-password" "$artifact_root/bin/hasp" version >/dev/null
HASP_HOME="$(mktemp -d)" HASP_MASTER_PASSWORD="artifact-password" "$artifact_root/bin/hasp" init >/dev/null

(cd ./apps/server && go test ./internal/profiles)
