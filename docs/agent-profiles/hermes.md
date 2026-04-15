# Hermes

## Config Surface

- Use HASP as Hermes' stdio MCP/tool server for brokered secret operations.
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

1. Bootstrap the local profile: `hasp bootstrap --profile hermes --project-root <repo> --alias secret_01=<item>`
2. Verify the broker locally: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp`
3. Register the command in Hermes' MCP or tool-server configuration.

## Session Behavior

- HASP creates a daemon-backed session when Hermes starts the stdio server.
- Keep long Hermes runs usable with project/secret `window` grants instead of repeated prompts.

## Success Signal

- Hermes lists only project-scoped HASP references.
- `hasp_run` and `hasp_inject` succeed without exposing raw managed values back to the caller.

## Safe Path

- `hasp_run`
- `hasp_inject`

## Convenience Path

- `hasp write-env`
- The broker warns when the destination is inside the bound project and requires explicit convenience approval.

## Failure Recovery

- Restart the HASP stdio process if Hermes loses the MCP connection.
- If the daemon rejects a provided session token, let HASP open a fresh session instead of reusing the stale one.

## Known Caveats

- `write-env` is intentionally outside the agent-safe guarantee once the file exists in the project.
