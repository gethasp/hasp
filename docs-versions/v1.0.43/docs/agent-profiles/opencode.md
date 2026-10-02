# OpenCode

## Config Example

`hasp agent connect opencode` installs the managed wrapper and a local MCP
entry for OpenCode 1.x. It uses `OPENCODE_CONFIG` when set, otherwise
`$XDG_CONFIG_HOME/opencode/opencode.json` or `~/.config/opencode/opencode.json`.

```json
{
  "mcp": {
    "hasp": {
      "type": "local",
      "command": ["/Users/alice/.hasp/bin/hasp-agent-opencode"],
      "enabled": true
    }
  }
}
```

Replace the example path with your managed wrapper path from
`hasp agent status opencode --json`. Setup preserves other JSON settings.
If the selected file uses JSONC comments or trailing commas, automatic setup
stops without changing that file. Add the entry manually, or select a separate
JSON file with `OPENCODE_CONFIG` for both setup and OpenCode.

OpenCode merges configuration sources. Project or inline settings can override
the global entry, so a saved file does not prove a live connection.
See [OpenCode configuration](https://opencode.ai/docs/config/) and
[local MCP servers](https://opencode.ai/docs/mcp-servers/).

## Session Behavior

Start the whole client with `hasp agent launch opencode -- opencode` from the
bound repository. The launcher establishes daemon process identity and an
inherited agent-safe environment for the client's ordinary shell tools.
An MCP wrapper alone protects its own process tree; it cannot attest sibling
shell processes in an otherwise unprotected client.

The MCP transport retains project sessions across tool calls. A fresh
connection or expired session needs new project consent. Use `grant_project`
and `grant_secret` explicitly, with `once`, `session`, or `window` as appropriate.
No setup command grants plaintext access. The operator can grant one-time
plaintext access to a protected session with `hasp session grant-plaintext`.

## Success Signal

1. `hasp agent status opencode --json` reports current configuration and wrapper.
2. OpenCode's HASP `hasp_status` tool reports `connection=connected` for that MCP
   transport. OpenCode may prefix the tool name with the server name.
3. Run `hasp agent status opencode --json` through OpenCode's ordinary Bash tool.
   A launcher-protected client reports `daemon_process_tree` or a validated
   `daemon_session_environment`. Run `hasp secret show NAME` for metadata;
   use `hasp_run` or `hasp_inject` for delivery.

For long commands, start a recoverable job and retain its `request_id`.
Recover its progress with `hasp_job_status` if the client loses a response.

## Failure Recovery

- Re-run `hasp agent connect opencode` for missing or outdated managed files.
- Use `opencode mcp list` and the client's `hasp_status` tool to check active
  configuration. Inspect project and inline overrides if the file is current
  but the client does not connect.
- Restart through `hasp agent launch opencode -- opencode` when the shell status
  does not observe a protected session. An environment guard alone cannot
  attach an operator's session grant.
- Retry a denied HASP tool call using its reported `grant_field` and an explicit
  duration. A consumed once grant requires fresh consent as its error explains.

## Known Caveats

The adapter writes the OpenCode 1.x `mcp.hasp` schema. It rejects a configuration
using `mcp.servers` rather than silently converting another schema.
Read-only diagnostics inspect the selected file and current command; they do
not claim to inspect every client override, another process's permissions, or
an active plaintext grant. Local process and environment protection do not
provide strong isolation from a hostile process running as the same user.
