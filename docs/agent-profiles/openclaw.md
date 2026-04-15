# OpenClaw

## Config Surface

- Use HASP as the stdio MCP/tool server OpenClaw launches for secret-aware tasks.
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

1. Bootstrap the local profile: `hasp bootstrap --profile openclaw --project-root <repo> --alias secret_01=<item>`
2. Verify the broker: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp`
3. Configure OpenClaw to invoke the HASP stdio command.

## Session Behavior

- HASP opens a daemon-backed session when OpenClaw connects.
- Use project and secret `window` grants for longer agent loops.

## Success Signal

- OpenClaw can list only bound aliases for the workspace.
- `hasp_inject` returns file paths outside the repo root.

## Safe Path

- `hasp_run`
- `hasp_inject`

## Convenience Path

- `hasp write-env`
- Convenience grants are explicit, audited, and tied to the same destination plus canonical secret identities.

## Failure Recovery

- If OpenClaw loses the tool connection, restart the HASP process and retry.
- If `write-env` fails after alias remapping, request a new convenience approval for the new secret set.

## Known Caveats

- Broker-managed repo protection covers installed hooks and HASP deploy wrappers, not arbitrary raw deploy commands.
