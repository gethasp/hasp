# Codex CLI

## Config Surface

- Prefer the wrapper or launcher path for Codex-style local agent workflows;
  use HASP as the generic stdio MCP server underneath it.
- Canonical command: `hasp agent mcp codex-cli`

## Config Example

```json
{
  "mcpServers": {
    "hasp": {
      "command": "hasp",
      "args": ["agent", "mcp", "codex-cli"]
    }
  }
}
```

## Setup

1. Bootstrap the local profile: `hasp bootstrap --profile codex-cli --project-root <repo> --alias secret_01=<item>`
2. Verify the tool surface: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp agent mcp codex-cli`
3. Register the MCP command in the Codex CLI config or launch wrapper you use
   locally.

Bootstrap may create a neutral repo alias such as `secret_01`, but day-to-day
usage should prefer safe named refs such as `@OPENAI_API_KEY` with
`hasp_run` or `hasp_inject`.

## Session Behavior

- `hasp agent mcp codex-cli` manages daemon-backed sessions internally when no explicit token
  is supplied, and wrapper or launcher paths propagate the token into the
  whole process tree.
- Use manual `hasp session open` only for debugging or controlled reuse outside the default flow.

## Success Signal

- The tool surface lists `hasp_list`, `hasp_run`, `hasp_inject`, `hasp_capture`, and `hasp_redact`.
- `hasp_list` returns only safe project-scoped metadata, including neutral aliases and named refs.

## Safe Path

- Use `hasp_run` for env-style command execution.
- Use `hasp_inject` when the workflow needs a real file path outside the repo root.
- Prefer named refs such as `@OPENAI_API_KEY` or `@GOOGLE_APPLICATION_CREDENTIALS` in those tool calls instead of recalling `secret_01`.
- Connected Codex CLI setups enable HASP agent-safe mode by default when
  launched through a HASP wrapper or launcher, so `hasp secret get --reveal`
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

- Restart `hasp mcp` if the stdio session stalls.
- Rebind the repo if the project root changed and the daemon reports a root mismatch.

## Known Caveats

- V1 uses local process-tree protection to prevent accidental exposure, not
  malicious same-user local processes.
