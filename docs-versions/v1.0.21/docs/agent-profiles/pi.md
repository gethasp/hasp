# Pi

## Config Surface

- Prefer `hasp setup --agent pi` or `hasp agent connect pi`; HASP writes a
  generated Pi package under `HASP_HOME/pi-package` and registers that package
  path in Pi's `settings.json`.
- Canonical broker command behind the generated extension: `hasp agent mcp pi`
- Pi's config directory follows `PI_CODING_AGENT_DIR` when that environment
  variable is set, otherwise it defaults to `~/.pi/agent`.

## Config Example

```json
{
  "packages": [
    "/Users/alice/.hasp/pi-package"
  ]
}
```

The package contains an extension that discovers HASP MCP tools from the
managed wrapper and registers them as Pi tools.

## Setup

1. Bootstrap the local profile: `hasp bootstrap --profile pi --project-root <repo> --alias secret_01=<item>`
2. Connect Pi: `hasp agent connect pi --project-root <repo>`
3. Verify Pi sees the package: `pi list`
4. Verify the broker locally: `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp agent mcp pi`

Bootstrap may create a neutral repo alias such as `secret_01`, but day-to-day
Pi usage should prefer safe named refs such as `@OPENAI_API_KEY` with
`hasp_run` or `hasp_inject`.

## Session Behavior

- The generated Pi extension starts the managed wrapper, which invokes
  `hasp agent mcp pi` and opens a daemon-backed session for the bound project
  when no explicit session token is supplied.
- Use broker-side project and secret `window` grants for longer Pi sessions
  instead of repeated manual approvals.
- If `PI_CODING_AGENT_DIR` points at an alternate Pi config directory, HASP
  installs the package reference there.

## Success Signal

- `pi list` includes the generated `HASP_HOME/pi-package` package path.
- Pi lists brokered HASP tools such as `hasp_list`, `hasp_run`, `hasp_inject`,
  `hasp_capture`, and `hasp_redact`.
- `hasp_list` returns only safe project-scoped metadata, including neutral
  aliases and named refs.

## Safe Path

- Use `hasp_run` for env-style command execution.
- Use `hasp_inject` when Pi needs a broker-owned file path outside the repo.
- Prefer named refs such as `@OPENAI_API_KEY` or `@GOOGLE_APPLICATION_CREDENTIALS`
  in those tool calls instead of recalling `secret_01`.
- Connected Pi setups enable HASP agent-safe mode through the managed wrapper,
  so `hasp secret get --reveal` and `--copy` are blocked inside protected
  workflows unless the operator first grants one-time plaintext access with
  `hasp session grant-plaintext`.

## Convenience Path

- Use `hasp write-env` only when a repo-visible env file is worth breaking the
  brokered no-plaintext-in-agent-context path.
- Expect an explicit convenience approval and a warning when the destination is
  inside the bound project.

## Failure Recovery

- Rerun `hasp agent connect pi --project-root <repo>` if the generated package
  path is missing from `pi list`.
- If the generated extension reports `hasp_status` instead of normal tools,
  verify the managed wrapper exists under `HASP_HOME/bin/hasp-agent-pi` and
  that `hasp agent mcp pi` can list tools from the same working tree.
- Rebind the repo if the project root changed and the daemon reports a root
  mismatch.

## Known Caveats

- Pi uses a package/extension surface rather than a native MCP config file, so
  HASP registers a generated local package instead of writing an `mcpServers`
  block.
- V1 uses daemon-issued local sessions and local process-tree protection, not
  strong same-user local isolation.
