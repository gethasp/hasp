# Cursor

## Config Surface

- Configure HASP as a stdio MCP server in Cursor's MCP settings.
- Canonical command: `hasp mcp`

## Config Example

```json
{
  "mcpServers": {
    "hasp": {
      "command": "hasp",
      "args": ["mcp"]
    }
  }
}
```

## Setup

1. Bootstrap the local profile: `hasp bootstrap --profile cursor --project-root <repo> --alias secret_01=<item>`
2. Verify the broker locally: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp`
3. Add the MCP entry shown above in Cursor.

## Session Behavior

- `hasp mcp` auto-opens a daemon-backed session for Cursor if one is not supplied.
- Use `window` grants for longer Cursor loops instead of repeated per-command prompts.
- Use `hasp session open` only for debugging or manual token inspection.

## Success Signal

- Cursor shows the HASP tool server as connected.
- `hasp_list` returns only the aliases you bound into the workspace.

## Safe Path

- Use `hasp_run` for brokered command execution.
- Use `hasp_inject` when Cursor needs file-based credentials without placing them in the repo.

## Convenience Path

- Use `hasp write-env` for `.env.local`-style files only when convenience is worth the exposure.
- Reuse is limited to the same project, destination path, and canonical secret set.

## Failure Recovery

- Reconnect the MCP server if Cursor loses the HASP tool connection.
- Regrant the project or secret window when the daemon reports an approval failure.

## Known Caveats

- Broker-managed deploy blocking only applies when you use HASP wrappers or installed hooks.
- Raw deploy commands outside HASP control remain warn-only in V1.
