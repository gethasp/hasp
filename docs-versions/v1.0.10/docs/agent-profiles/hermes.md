# Hermes

## Config Surface

- Prefer Hermes' wrapper or launcher path when available; use HASP as the
  stdio MCP/tool server underneath it.
- Canonical command: `hasp agent mcp hermes`

## Config Example

```json
{
  "mcpServers": {
    "hasp": {
      "command": "hasp",
      "args": ["agent", "mcp", "hermes"]
    }
  }
}
```

## Setup

1. Bootstrap the local profile: `hasp bootstrap --profile hermes --project-root <repo> --alias secret_01=<item>`
2. Verify the broker locally: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp agent mcp hermes`
3. Register the command in Hermes' MCP or tool-server configuration, or wire
   the same command into the wrapper or launcher path you already use.

Bootstrap may create a neutral repo alias such as `secret_01`, but day-to-day
usage should prefer safe named refs such as `@OPENAI_API_KEY` with
`hasp_run` or `hasp_inject`.

## Session Behavior

- HASP creates a daemon-backed session when Hermes starts the stdio server,
  and wrapper or launcher paths propagate that session into subprocesses.
- Keep long Hermes runs usable with project/secret `window` grants instead of repeated prompts.

## Success Signal

- Hermes lists only safe project-scoped HASP metadata, including neutral aliases and named refs.
- `hasp_run` and `hasp_inject` succeed without exposing raw managed values back to the caller.

## Safe Path

- `hasp_run`
- `hasp_inject`
- Prefer named refs such as `@OPENAI_API_KEY` or `@GOOGLE_APPLICATION_CREDENTIALS` in those tool calls instead of recalling `secret_01`.
- Connected Hermes setups enable HASP agent-safe mode by default when launched
  through a HASP wrapper or launcher, so `hasp secret get --reveal` and
  `--copy` are blocked inside protected workflows unless the operator first
  grants one-time plaintext access with `hasp session grant-plaintext`.
- For stronger subprocess coverage, prefer launching Hermes from
  `hasp agent shell hermes` or `hasp agent launch hermes -- <command>` so
  `HASP_AGENT_SAFE_MODE` and `HASP_SESSION_TOKEN` reach the whole agent
  process tree.

## Convenience Path

- `hasp write-env`
- The broker warns when the destination is inside the bound project and requires explicit convenience approval.

## Failure Recovery

- Restart the HASP stdio process if Hermes loses the MCP connection.
- If the daemon rejects a provided session token, let HASP open a fresh session instead of reusing the stale one.

## Known Caveats

- `write-env` is intentionally outside the agent-safe guarantee once the file
  exists in the project.
