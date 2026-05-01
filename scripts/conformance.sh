#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

stop_scoped_daemon() {
  local bin_path="$1"
  local hasp_home="$2"
  local socket_path="${3:-}"
  [[ -x "$bin_path" && -n "$hasp_home" ]] || return 0

  local pid_file="$hasp_home/runtime/daemon.pid"
  local effective_socket="$socket_path"
  local pid=""
  local verified_pid=""
  if [[ -z "$effective_socket" ]]; then
    effective_socket="$hasp_home/runtime/daemon.sock"
  fi
  if [[ -f "$pid_file" ]]; then
    pid="$(tr -d '[:space:]' <"$pid_file" 2>/dev/null || true)"
    if pid_matches_scoped_daemon "$pid" "$effective_socket"; then
      verified_pid="$pid"
    fi
  fi

  if [[ -n "$verified_pid" ]]; then
    env HASP_HOME="$hasp_home" HASP_SOCKET="$effective_socket" "$bin_path" daemon stop >/dev/null 2>&1 || true
  fi

  if [[ -n "$verified_pid" ]]; then
    kill "$verified_pid" >/dev/null 2>&1 || true
    sleep 1
    kill -9 "$verified_pid" >/dev/null 2>&1 || true
  fi

  /bin/rm -f "$pid_file" "$effective_socket"
}

pid_matches_scoped_daemon() {
  local pid="$1"
  local socket_path="$2"
  [[ -n "$pid" && -n "$socket_path" ]] || return 1

  local command=""
  command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
  [[ "$command" == *" daemon serve"* ]] || return 1
  command -v lsof >/dev/null 2>&1 || return 1
  lsof -a -p "$pid" -U -Fn 2>/dev/null | grep -F "n$socket_path" >/dev/null 2>&1
}

make verify-ci
bash ./scripts/release-smoke.sh
make evals
make release-smoke

temp_home="$(mktemp -d)"
conformance_gpg_home="$(mktemp -d)"
artifact_dir=""
cleanup_conformance() {
  stop_scoped_daemon "./bin/hasp" "$temp_home"
  /bin/rm -rf "$temp_home" "$conformance_gpg_home" "${artifact_dir:-}"
}
trap cleanup_conformance EXIT
export HASP_HOME="$temp_home"
export HASP_MASTER_PASSWORD="conformance-password"
chmod 700 "$conformance_gpg_home"
export GNUPGHOME="$conformance_gpg_home"
unset HASP_RELEASE_GPG_KEY_ID
unset HASP_RELEASE_GPG_HOMEDIR
unset HASP_RELEASE_GPG_PASSPHRASE
unset HASP_RELEASE_GPG_PASSPHRASE_FILE
export HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING=1
export HASP_UPGRADE_TRUST_ROOTS_HEX="${HASP_UPGRADE_TRUST_ROOTS_HEX:-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}"

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
"$artifact_root/bin/hasp" version --json | grep -q '"upgrade_trust_roots":true'
case "$(cat "$artifact_root/QUICKSTART.md")" in
  *make\ build*|*./hasp\ version*)
    echo "Packaged quickstart is not artifact-specific" >&2
    exit 1
    ;;
esac
HASP_HOME="$(mktemp -d)" HASP_MASTER_PASSWORD="artifact-password" "$artifact_root/bin/hasp" version >/dev/null
HASP_HOME="$(mktemp -d)" HASP_MASTER_PASSWORD="artifact-password" "$artifact_root/bin/hasp" init >/dev/null

(cd ./apps/server && go test -tags=hasp_test_fastkdf ./internal/profiles)
