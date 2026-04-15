# Aider

## Config Surface

- Run HASP as the stdio MCP/tool process that Aider can invoke for brokered secret operations.
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

1. Bootstrap the local profile: `hasp bootstrap --profile aider --project-root <repo> --alias secret_01=<item>`
2. Verify the broker locally: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp`
3. Point Aider at the stdio command shown above.

## Session Behavior

- `hasp mcp` opens a fresh daemon-backed session when Aider connects.
- Use broker-side project and secret `window` grants for longer Aider sessions.

## Success Signal

- Aider can call `hasp_list` and see only project-scoped aliases.
- `hasp_run` succeeds without returning raw managed values in output.

## Safe Path

- `hasp_run`
- `hasp_inject`

## Convenience Path

- `hasp write-env`
- The user must approve convenience materialization explicitly for each destination/path scope.

## Failure Recovery

- Restart the HASP stdio server if Aider loses the connection.
- If capture fails, retry with explicit `grant_project` and `grant_write` inputs so the broker can audit the write.

## Known Caveats

- `capture` is a containment path for candidate secrets, not proof the value never touched agent context beforehand.
