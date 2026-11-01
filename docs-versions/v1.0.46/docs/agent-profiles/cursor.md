# Cursor

## Config Surface

- Prefer Cursor's wrapper or launcher path when available; use HASP as the
  stdio MCP server underneath it.
- Canonical command: `hasp agent mcp cursor`

## Config Example

```json
{
  "mcpServers": {
    "hasp": {
      "command": "hasp",
      "args": ["agent", "mcp", "cursor"]
    }
  }
}
```

## Setup

1. Bootstrap the local profile: `hasp bootstrap --profile cursor --project-root <repo> --alias secret_01=<item>`
2. Verify the broker locally: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp agent mcp cursor`
3. Add the MCP entry shown above in Cursor, or wire the same command into the
   wrapper or launcher path you already use.

Bootstrap may create a neutral repo alias such as `secret_01`, but day-to-day
usage should prefer safe named refs such as `@OPENAI_API_KEY` with
`hasp_run` or `hasp_inject`.

## Session Behavior

- `hasp agent mcp cursor` auto-opens a daemon-backed session for Cursor if one is not
  supplied, and the wrapper or launcher path propagates the session token to
  subprocesses.
- Use `window` grants for longer Cursor loops instead of repeated per-command prompts.
- Use `hasp session open` only for debugging or manual token inspection.

## Success Signal

- Cursor shows the HASP tool server as connected.
- `hasp_list` returns only safe workspace metadata, including neutral aliases and named refs.

## Safe Path

- Use `hasp_run` for brokered command execution.
- Use `hasp_inject` when Cursor needs file-based credentials without placing them in the repo.
- Prefer named refs such as `@OPENAI_API_KEY` or `@GOOGLE_APPLICATION_CREDENTIALS` in those tool calls instead of recalling `secret_01`.
- Connected Cursor setups enable HASP agent-safe mode by default when launched
  through a HASP wrapper or launcher, so `hasp secret get --reveal` and
  `--copy` are blocked inside protected workflows unless the operator first
  grants one-time plaintext access with `hasp session grant-plaintext`.
- For stronger subprocess coverage, prefer launching Cursor from
  `hasp agent shell cursor` or `hasp agent launch cursor -- <command>` so
  `HASP_AGENT_SAFE_MODE` and `HASP_SESSION_TOKEN` reach the whole agent
  process tree.

## Convenience Path

- Use `hasp write-env` for `.env.local`-style files only when convenience is worth the exposure.
- Reuse is limited to the same project, destination path, and canonical secret set.

## Failure Recovery

- Reconnect the MCP server if Cursor loses the HASP tool connection.
- Regrant the project or secret window when the daemon reports an approval failure.

## Known Caveats

- Broker-managed deploy blocking only applies when you use HASP wrappers or
  installed hooks, which is the privacy-preserving process-tree boundary.
- Raw deploy commands outside HASP control remain warn-only in V1.
