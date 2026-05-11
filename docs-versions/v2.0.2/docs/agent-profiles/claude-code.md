# Claude Code

## Config Surface

- Prefer Claude Code's wrapper or launcher path when available; use HASP as
  the stdio MCP server underneath it.
- Canonical command: `hasp agent mcp claude-code`

## Config Example

```json
{
  "mcpServers": {
    "hasp": {
      "command": "hasp",
      "args": ["agent", "mcp", "claude-code"]
    }
  }
}
```

## Setup

1. Bootstrap the local profile: `hasp bootstrap --profile claude-code --project-root <repo> --alias secret_01=<item>`
2. Verify the broker: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp agent mcp claude-code`
3. Add the MCP entry shown above to Claude Code, or wire the same command into
   the wrapper or launcher path you already use.

Bootstrap may create a neutral repo alias such as `secret_01`, but daily
Claude Code usage should prefer the safe named ref form such as
`@OPENAI_API_KEY`. HASP resolves that named ref back to the repo binding
internally.

Design direction:

- the target top-level setup surface should be wrapper/launcher-first, with
  `hasp agent connect claude` as the desired top-level entry
- profile bootstrap remains the current compatibility path for the shipped V1 runtime

## Session Behavior

- `hasp agent mcp claude-code` auto-opens a daemon-backed session for the bound project when the
  caller does not provide one, and the wrapper or launcher path propagates the
  session token to subprocesses.
- Use `hasp session open` only for debugging or when you intentionally want to inspect session state.
- Long Claude Code runs should use broker-side `window` grants, not repeated manual prompts.

## Success Signal

- Claude Code lists `hasp_list`, `hasp_run`, `hasp_inject`, `hasp_capture`, `hasp_secret_add`, `hasp_secret_update`, `hasp_secret_delete`, `hasp_secret_get`, `hasp_secret_expose`, `hasp_secret_hide`, and `hasp_redact`.
- `hasp_list` returns only safe project-scoped metadata, including neutral aliases and named refs.

## Safe Path

- Use `hasp_run` for command execution.
- Use `hasp_inject` for broker-owned file materialization outside the repo.
- Prefer named refs such as `@OPENAI_API_KEY` or `@GOOGLE_APPLICATION_CREDENTIALS` when calling `hasp_run` or `hasp_inject`.
- Use `hasp_secret_expose` when the repo needs an existing personal-vault secret.
- Use `hasp_secret_add` when the user wants the agent to store a new secret and keep working in the same chat flow.
- Connected Claude Code setups enable HASP agent-safe mode by default when
  launched through a HASP wrapper or launcher, so `hasp secret get --reveal`
  and `--copy` are blocked inside protected workflows unless the operator first
  grants one-time plaintext access with `hasp session grant-plaintext`.
- For stronger subprocess coverage, prefer launching Claude Code from
  `hasp agent shell claude-code` or `hasp agent launch claude-code -- <command>`
  so `HASP_AGENT_SAFE_MODE` and `HASP_SESSION_TOKEN` reach the whole agent
  process tree.

## Convenience Path

- Use `hasp write-env` only when a repo-visible env file is worth breaking the agent-safe guarantee.
- Expect an explicit convenience approval and a warning when the destination is inside the bound project.

## Failure Recovery

- If tools fail with a session error, restart the MCP server or rerun the Claude Code command so HASP can open a fresh session.
- If tools fail with an approval error, grant the project or secret window inside HASP and retry.

## Known Caveats

- Raw `write-env` output files are convenience materialization, not agent-safe broker flow.
- Raw `hasp secret get --reveal` is blocked inside protected agent workflows unless the operator first grants one-time plaintext access with `hasp session grant-plaintext`.
- V1 uses daemon-issued local sessions and local process-tree protection, not
  strong same-user local isolation.
