# OpenClaw

## Config Surface

- Prefer OpenClaw's wrapper or launcher path when available; use HASP as the
  stdio MCP/tool server underneath it.
- Canonical command: `hasp agent mcp openclaw`

## Config Example

```json
{
  "mcpServers": {
    "hasp": {
      "command": "hasp",
      "args": ["agent", "mcp", "openclaw"]
    }
  }
}
```

## Setup

1. Bootstrap the local profile: `hasp bootstrap --profile openclaw --project-root <repo> --alias secret_01=<item>`
2. Verify the broker: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp agent mcp openclaw`
3. Configure OpenClaw to invoke the HASP stdio command, or wire the same
   command into the wrapper or launcher path you already use.

Bootstrap may create a neutral repo alias such as `secret_01`, but day-to-day
usage should prefer safe named refs such as `@OPENAI_API_KEY` with
`hasp_run` or `hasp_inject`.

## Session Behavior

- HASP opens a daemon-backed session when OpenClaw connects, and wrapper or
  launcher paths propagate that session into subprocesses.
- Use project and secret `window` grants for longer agent loops.

## Success Signal

- OpenClaw can list only safe workspace metadata, including neutral aliases and named refs.
- `hasp_inject` returns file paths outside the repo root.

## Safe Path

- `hasp_run`
- `hasp_inject`
- Prefer named refs such as `@OPENAI_API_KEY` or `@GOOGLE_APPLICATION_CREDENTIALS` in those tool calls instead of recalling `secret_01`.
- Connected OpenClaw setups enable HASP agent-safe mode by default when
  launched through a HASP wrapper or launcher, so `hasp secret get --reveal`
  and `--copy` are blocked inside protected workflows unless the operator first
  grants one-time plaintext access with `hasp session grant-plaintext`.
- For stronger subprocess coverage, prefer launching OpenClaw from
  `hasp agent shell openclaw` or `hasp agent launch openclaw -- <command>` so
  `HASP_AGENT_SAFE_MODE` and `HASP_SESSION_TOKEN` reach the whole agent
  process tree.

## Convenience Path

- `hasp write-env`
- Convenience grants are explicit, audited, and tied to the same destination plus canonical secret identities.

## Failure Recovery

- If OpenClaw loses the tool connection, restart the HASP process and retry.
- If `write-env` fails after alias remapping, request a new convenience approval for the new secret set.

## Known Caveats

- Broker-managed repo protection covers installed hooks and HASP deploy
  wrappers, not arbitrary raw deploy commands.
