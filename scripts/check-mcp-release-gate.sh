#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if repo_root="$(git -C "$script_dir/.." rev-parse --show-toplevel 2>/dev/null)"; then
  :
else
  repo_root="$(cd "$script_dir/.." && pwd)"
fi

usage() {
  cat <<'EOF'
Usage: check-mcp-release-gate.sh [--bin <path> | --build] [--timeout <seconds>]

Hard-fail a release when HASP's stdio MCP surface is missing, stale, or slow.
The gate verifies:
  - bare `hasp mcp` initialize + tools/list
  - managed `hasp agent mcp claude-code` and `codex-cli`
  - generated Claude/Codex MCP config points at executable managed wrappers
  - managed wrappers can initialize and list tools within the timeout
EOF
}

hasp_bin=""
build_binary=0
probe_timeout="${HASP_MCP_RELEASE_GATE_TIMEOUT:-5}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin)
      if [[ -z "${2:-}" ]]; then
        usage >&2
        exit 2
      fi
      hasp_bin="$2"
      shift 2
      ;;
    --build)
      build_binary=1
      shift
      ;;
    --timeout)
      if [[ -z "${2:-}" ]]; then
        usage >&2
        exit 2
      fi
      probe_timeout="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

tmp_dir="$(mktemp -d)"
cleanup() {
  if [[ -n "${hasp_bin:-}" && -x "${hasp_bin:-}" && -n "${HASP_HOME:-}" ]]; then
    "$hasp_bin" daemon stop >/dev/null 2>&1 || true
  fi
  /bin/rm -rf "$tmp_dir"
}
trap cleanup EXIT

if [[ "$build_binary" == "1" ]]; then
  hasp_bin="$tmp_dir/hasp"
  export HASP_TEAM_ID="${HASP_TEAM_ID:-TEAMID1234}"
  HASP_BUILD_OUTPUT="$hasp_bin" bash "$repo_root/scripts/build.sh" >/dev/null
elif [[ -z "$hasp_bin" ]]; then
  hasp_bin="$(command -v hasp || true)"
fi

if [[ -z "$hasp_bin" || ! -x "$hasp_bin" ]]; then
  printf 'MCP release gate: hasp binary is not executable: %s\n' "${hasp_bin:-<unset>}" >&2
  exit 1
fi

if [[ "$hasp_bin" != /* ]]; then
  hasp_bin="$(cd "$(dirname "$hasp_bin")" && pwd)/$(basename "$hasp_bin")"
fi

export HOME="$tmp_dir/user-home"
export XDG_CONFIG_HOME="$HOME/.config"
export HASP_HOME="$tmp_dir/hasp-home"
export HASP_SOCKET="$HASP_HOME/runtime/daemon.sock"
export HASP_MASTER_PASSWORD="release-mcp-gate-password"
export HASP_BACKUP_PASSPHRASE="release-mcp-gate-backup"
export HASP_TEST=1
export HASP_DAEMON_STARTUP_TIMEOUT="${HASP_DAEMON_STARTUP_TIMEOUT:-2s}"
export HASP_AGENT_MCP_PREFLIGHT_TIMEOUT="${HASP_AGENT_MCP_PREFLIGHT_TIMEOUT:-250ms}"

/bin/mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$HASP_HOME"

project_root="$tmp_dir/project"
/bin/mkdir -p "$project_root"
git -C "$project_root" init >/dev/null 2>&1

"$hasp_bin" init >/dev/null
"$hasp_bin" agent connect claude-code --json --project-root "$project_root" >/dev/null
"$hasp_bin" agent connect codex-cli --json --project-root "$project_root" >/dev/null

validate_generated_config() {
  python3 - "$HOME" "$HASP_HOME" <<'PY'
import json
import os
import re
import stat
import sys
from pathlib import Path

home = Path(sys.argv[1])
hasp_home = Path(sys.argv[2])

expected = {
    "claude-code": hasp_home / "bin" / "hasp-agent-claude-code",
    "codex-cli": hasp_home / "bin" / "hasp-agent-codex-cli",
}

def fail(message: str) -> None:
    raise SystemExit(f"MCP release gate: {message}")

for agent_id, wrapper in expected.items():
    if not wrapper.exists():
        fail(f"missing managed wrapper for {agent_id}: {wrapper}")
    mode = wrapper.stat().st_mode
    if not (mode & stat.S_IXUSR):
        fail(f"managed wrapper is not executable for {agent_id}: {wrapper}")
    text = wrapper.read_text(encoding="utf-8")
    if "# hasp-managed agent wrapper" not in text or f'agent mcp "{agent_id}"' not in text:
        fail(f"managed wrapper does not launch agent MCP for {agent_id}: {wrapper}")

claude_config = home / ".claude.json"
if not claude_config.exists():
    fail(f"Claude MCP config was not generated: {claude_config}")
claude = json.loads(claude_config.read_text(encoding="utf-8"))
claude_hasp = claude.get("mcpServers", {}).get("hasp", {})
if claude_hasp.get("command") != str(expected["claude-code"]):
    fail(f"Claude MCP command points at {claude_hasp.get('command')!r}, want {expected['claude-code']}")
if "HASP_MASTER_PASSWORD" in json.dumps(claude_hasp):
    fail("Claude MCP config contains master-password material")

codex_config = home / ".codex" / "config.toml"
if not codex_config.exists():
    fail(f"Codex MCP config was not generated: {codex_config}")
codex_text = codex_config.read_text(encoding="utf-8")
match = re.search(r'(?ms)^\[mcp_servers\.hasp\]\s*^command\s*=\s*"([^"]+)"', codex_text)
if not match:
    fail("Codex MCP config is missing [mcp_servers.hasp] command")
if match.group(1) != str(expected["codex-cli"]):
    fail(f"Codex MCP command points at {match.group(1)!r}, want {expected['codex-cli']}")
if "HASP_MASTER_PASSWORD" in codex_text:
    fail("Codex MCP config contains master-password material")
PY
}

probe_mcp() {
  local label="$1"
  shift
  python3 - "$label" "$probe_timeout" -- "$@" <<'PY'
import json
import subprocess
import sys
import time

label = sys.argv[1]
try:
    timeout = float(sys.argv[2])
except ValueError as exc:
    raise SystemExit(f"MCP release gate: invalid timeout {sys.argv[2]!r}") from exc
sep = sys.argv.index("--")
cmd = sys.argv[sep + 1 :]
request = "\n".join([
    json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "hasp-release-gate", "version": "1"},
        },
    }),
    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    "",
])
start = time.monotonic()
try:
    proc = subprocess.run(
        cmd,
        input=request,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
except subprocess.TimeoutExpired as exc:
    raise SystemExit(f"MCP release gate: {label} timed out after {timeout:.2f}s") from exc
elapsed = time.monotonic() - start
if proc.returncode != 0:
    raise SystemExit(
        f"MCP release gate: {label} exited {proc.returncode}\n"
        f"stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}"
    )
responses = []
for raw in proc.stdout.splitlines():
    line = raw.strip()
    if not line:
        continue
    try:
        responses.append(json.loads(line))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"MCP release gate: {label} emitted non-JSON line: {line!r}") from exc
by_id = {response.get("id"): response for response in responses}
init = by_id.get(1)
tools = by_id.get(2)
if not init or init.get("error"):
    raise SystemExit(f"MCP release gate: {label} initialize failed: {init!r}")
if init.get("result", {}).get("protocolVersion") != "2025-06-18":
    raise SystemExit(f"MCP release gate: {label} negotiated unexpected protocol: {init!r}")
if not tools or tools.get("error"):
    raise SystemExit(f"MCP release gate: {label} tools/list failed: {tools!r}")
names = {tool.get("name") for tool in tools.get("result", {}).get("tools", [])}
if "hasp_list" not in names:
    raise SystemExit(f"MCP release gate: {label} missing hasp_list in tool catalog: {sorted(names)!r}")
print(f"[ok] {label} initialize + tools/list in {elapsed:.2f}s")
PY
}

validate_generated_config
probe_mcp "bare hasp mcp" "$hasp_bin" mcp
probe_mcp "Claude agent mcp" "$hasp_bin" agent mcp claude-code
probe_mcp "Codex agent mcp" "$hasp_bin" agent mcp codex-cli
probe_mcp "Claude managed wrapper" "$HASP_HOME/bin/hasp-agent-claude-code"
probe_mcp "Codex managed wrapper" "$HASP_HOME/bin/hasp-agent-codex-cli"

printf 'MCP release gate passed\n'
