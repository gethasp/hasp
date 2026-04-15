# Claude Code

## Config Surface

- Configure HASP as a stdio MCP server in Claude Code's MCP settings.
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

1. Bootstrap the local profile: `hasp bootstrap --profile claude-code --project-root <repo> --alias secret_01=<item>`
2. Verify the broker: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp`
3. Add the MCP entry shown above to Claude Code.

## Session Behavior

- `hasp mcp` auto-opens a daemon-backed session for the bound project when the caller does not provide one.
- Use `hasp session open` only for debugging or when you intentionally want to inspect session state.
- Long Claude Code runs should use broker-side `window` grants, not repeated manual prompts.

## Success Signal

- Claude Code lists `hasp_list`, `hasp_run`, `hasp_inject`, `hasp_capture`, and `hasp_redact`.
- `hasp_list` returns only project-scoped aliases, kinds, policy levels, and lease state.

## Safe Path

- Use `hasp_run` for command execution.
- Use `hasp_inject` for broker-owned file materialization outside the repo.

## Convenience Path

- Use `hasp write-env` only when a repo-visible env file is worth breaking the agent-safe guarantee.
- Expect an explicit convenience approval and a warning when the destination is inside the bound project.

## Failure Recovery

- If tools fail with a session error, restart the MCP server or rerun the Claude Code command so HASP can open a fresh session.
- If tools fail with an approval error, grant the project or secret window inside HASP and retry.

## Known Caveats

- Raw `write-env` output files are convenience materialization, not agent-safe broker flow.
- V1 uses daemon-issued local sessions, not strong same-user local isolation.
