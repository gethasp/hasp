# Codex CLI

## Config Surface

- Use HASP as a generic stdio MCP server for Codex-style local agent workflows.
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

1. Bootstrap the local profile: `hasp bootstrap --profile codex-cli --project-root <repo> --alias secret_01=<item>`
2. Verify the tool surface: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp`
3. Register the MCP command in the Codex CLI config or launch wrapper you use locally.

## Session Behavior

- `hasp mcp` manages daemon-backed sessions internally when no explicit token is supplied.
- Use manual `hasp session open` only for debugging or controlled reuse outside the default flow.

## Success Signal

- The tool surface lists `hasp_list`, `hasp_run`, `hasp_inject`, `hasp_capture`, and `hasp_redact`.
- `hasp_list` returns only safe project-scoped metadata.

## Safe Path

- Use `hasp_run` for env-style command execution.
- Use `hasp_inject` when the workflow needs a real file path outside the repo root.

## Convenience Path

- Use `hasp write-env` only for explicit repo-visible materialization.
- Reuse depends on the same destination plus the same canonical secret set, not just alias names.

## Failure Recovery

- Restart `hasp mcp` if the stdio session stalls.
- Rebind the repo if the project root changed and the daemon reports a root mismatch.

## Known Caveats

- V1 protects common sloppy workflows, not malicious same-user local processes.
