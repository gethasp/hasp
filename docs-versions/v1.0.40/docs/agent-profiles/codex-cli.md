# Codex CLI

## Config Surface

- Prefer the wrapper or launcher path for Codex-style local agent workflows;
  use HASP as the generic stdio MCP server underneath it.
- Canonical command: `hasp agent mcp codex-cli`

## Config Example

`hasp agent connect codex-cli` writes the managed entry to
`$CODEX_HOME/config.toml`, or `~/.codex/config.toml` when `CODEX_HOME` is unset.
The Codex CLI uses TOML:

```toml
[mcp_servers.hasp]
command = "/Users/alice/.hasp/bin/hasp-agent-codex-cli"
```

Replace the example path with the wrapper path reported by
`hasp agent status codex-cli --json`. See the
[Codex MCP configuration](https://developers.openai.com/codex/mcp).

## Setup

1. Bootstrap the local profile: `hasp bootstrap --profile codex-cli --project-root <repo> --alias secret_01=<item>`
2. Install the managed configuration: `hasp agent connect codex-cli`
3. Verify the tool surface: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp agent mcp codex-cli`
4. Start the whole client: `hasp agent launch codex-cli -- codex`

Bootstrap may create a neutral repo alias such as `secret_01`, but day-to-day
usage should prefer safe named refs such as `@OPENAI_API_KEY` with
`hasp_run` or `hasp_inject`.

## Session Behavior

- The MCP wrapper protects its own process tree. It cannot establish protection
  for the client's sibling shell tools. `hasp agent launch codex-cli -- codex`
  establishes daemon identity and an agent-safe environment for the whole client.
- The MCP transport retains project sessions across tool calls; a new transport
  or expired session requires new consent.
- Use manual `hasp session open` only for debugging or controlled reuse outside the default flow.

## Success Signal

- `hasp agent status codex-cli --json` reports installation and the current
  command's process protection separately. Run it through Codex's ordinary
  shell tool to inspect that process tree.
- The client's `hasp_status` MCP tool reports that its transport is connected;
  it does not claim shell protection.

- The default tool surface lists `hasp_list`, `hasp_targets`,
  `hasp_target_explain`, `hasp_check`, `hasp_status`, `hasp_run`, `hasp_inject`,
  `hasp_job_start`, `hasp_job_status`, `hasp_job_cancel`, `hasp_secret_get`, and
  `hasp_redact`.
- `hasp_list` returns only safe project-scoped metadata, including neutral aliases and named refs.

## Safe Path

- Use `hasp_run` for env-style command execution.
- Use `hasp_inject` when the workflow needs a real file path outside the repo root.
- When `.hasp.manifest.json` defines targets, call `hasp_targets` first and
  prefer `hasp_run` or `hasp_inject` with `target` over raw broad mappings.
- If the repo has no manifest yet, create a value-free template with
  `hasp template add <target> --env NAME=@NAME -- <command>` when local edits
  are allowed. Do not put secret values in `.hasp.manifest.json`.
- Before first use of a repo-controlled target command, inspect with
  `hasp run --target <target> --explain --dry-run`, then run
  `hasp template review <target>`. Brokered target execution fails until the
  local review signature exists and is current.
- Prefer named refs such as `@OPENAI_API_KEY` or `@GOOGLE_APPLICATION_CREDENTIALS` in those tool calls instead of recalling `secret_01`.
- Default Codex CLI MCP cannot auto-expose existing vault items. Ask the
  operator to run `hasp secret expose NAME --project-root <repo>`, or use a
  trusted local harness with unsafe tools enabled and `hasp session
  grant-mutation`.
- The whole-client launcher enables HASP agent-safe mode, so `hasp secret get --reveal`
  and `--copy` are blocked inside protected workflows unless the operator first
  grants one-time plaintext access with `hasp session grant-plaintext`.
- For stronger subprocess coverage, prefer launching Codex from
  `hasp agent shell codex-cli` or `hasp agent launch codex-cli -- <command>`
  so `HASP_AGENT_SAFE_MODE` and `HASP_SESSION_TOKEN` reach the whole agent
  process tree.

## Convenience Path

- Use `hasp write-env` only for explicit repo-visible materialization.
- Reuse depends on the same destination and the same canonical secret set.
  Alias names alone are not enough.

## Failure Recovery

- Use `hasp_job_start` for long commands and retain the request ID. If a response
  is lost, use `hasp_job_status` before repeating any command.
- Re-run `hasp agent connect codex-cli` to repair managed files. Restart Codex
  through its HASP launcher if shell diagnostics do not observe protection.
- Rebind the repo if the project root changed and the daemon reports a root mismatch.

## Known Caveats

- V1 uses local process-tree protection to prevent accidental exposure, not
  malicious same-user local processes.
