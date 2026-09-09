# Aider

## Config Surface

- Prefer Aider's wrapper or launcher path when you need subprocess-safe
  propagation; use HASP as the stdio MCP/tool process underneath it.
- Canonical command: `hasp agent mcp aider`

## Config Example

```json
{
  "mcpServers": {
    "hasp": {
      "command": "hasp",
      "args": ["agent", "mcp", "aider"]
    }
  }
}
```

## Setup

1. Bootstrap the local profile: `hasp bootstrap --profile aider --project-root <repo> --alias secret_01=<item>`
2. Verify the broker locally: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp agent mcp aider`
3. Point Aider at the stdio command shown above, or place that command behind
   the wrapper or launcher path you already use.

Bootstrap may create a neutral repo alias such as `secret_01`, but day-to-day
usage should prefer safe named refs such as `@OPENAI_API_KEY` with
`hasp_run` or `hasp_inject`.

## Session Behavior

- `hasp agent mcp aider` opens a fresh daemon-backed session when Aider connects, and the
  wrapper or launcher path propagates that session into spawned subprocesses.
- Use broker-side project and secret `window` grants for longer Aider sessions.

## Success Signal

- Aider can call `hasp_list` and see only safe project-scoped metadata, including neutral aliases and named refs.
- `hasp_run` succeeds without returning raw managed values in output.

## Safe Path

- `hasp_run`
- `hasp_inject`
- Prefer named refs such as `@OPENAI_API_KEY` or `@GOOGLE_APPLICATION_CREDENTIALS` in those tool calls instead of recalling `secret_01`.
- Connected Aider setups enable HASP agent-safe mode by default when launched
  through a HASP wrapper or launcher, so `hasp secret get --reveal` and
  `--copy` are blocked inside protected workflows unless the operator first
  grants one-time plaintext access with `hasp session grant-plaintext`.
- For stronger subprocess coverage, prefer launching Aider from
  `hasp agent shell aider` or `hasp agent launch aider -- <command>` so
  `HASP_AGENT_SAFE_MODE` and `HASP_SESSION_TOKEN` reach the whole agent
  process tree.

## Convenience Path

- `hasp write-env`
- The user must approve convenience materialization explicitly for each destination/path scope.

## Failure Recovery

- Restart the HASP stdio server if Aider loses the connection.
- If capture fails, retry with explicit `grant_project` and `grant_write` inputs so the broker can audit the write.

## Known Caveats

- `capture` is a containment path for candidate secrets, not proof the value
  never touched the launched process tree beforehand.
