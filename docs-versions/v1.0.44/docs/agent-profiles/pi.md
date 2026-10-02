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

- The generated extension keeps one MCP connection, retaining project sessions
  across calls. Explicit project roots stay isolated. A transport failure is
  never retried automatically because the command may already have run.
- The extension sets `HASP_AGENT_SAFE_MODE` in Pi's parent process so ordinary
  Bash children inherit a plaintext guard. This is an environment guard, not a
  daemon-attested process identity. Use `hasp agent launch pi -- pi` for process
  protection and operator-issued plaintext grants.
- `session` and `window` grants persist for their stated lifetimes. Fresh
  connections or expired sessions require fresh consent.
- Use `hasp_job_start` for long commands and recover with `hasp_job_status`.
  Cancellation of a synchronous Pi tool call reports an unknown outcome;
  inspect its effects before repeating it.
- If `PI_CODING_AGENT_DIR` points at an alternate Pi config directory, HASP
  installs the package reference there.

## Success Signal

- Pi's `hasp_status` reports whether the extension loaded, whether its MCP
  transport is connected, and whether the inherited environment guard is set.
- Run `hasp agent status pi --json` through Pi's ordinary Bash tool to inspect
  the current process tree. A launcher-protected client reports daemon identity.

- `pi list` includes the generated `HASP_HOME/pi-package` package path.
- Pi lists brokered HASP tools such as `hasp_list`, `hasp_run`, `hasp_inject`,
  `hasp_secret_get`, and `hasp_redact`.
- `hasp_list` returns only safe project-scoped metadata, including neutral
  aliases and named refs.

## Safe Path

- Use `hasp_run` for env-style command execution.
- Use `hasp_inject` when Pi needs a broker-owned file path outside the repo.
- Prefer named refs such as `@OPENAI_API_KEY` or `@GOOGLE_APPLICATION_CREDENTIALS`
  in those tool calls instead of recalling `secret_01`.
- The parent extension guard and whole-client launcher block plaintext, so `hasp secret get --reveal` and `--copy` are blocked inside protected
  workflows unless the operator first grants one-time plaintext access with
  `hasp session grant-plaintext`.

## Convenience Path

For SSH or tools that accept stdin, keep expansion inside a brokered shell.
Use the [brokered handoff examples](https://gethasp.com/docs/brokered-handoffs/)
for env-to-stdin, file-to-stdin, and temporary-path lifetimes.

- Use `hasp write-env` only when a repo-visible env file is worth breaking the
  brokered no-plaintext-in-agent-context path.
- Expect an explicit convenience approval and a warning when the destination is
  inside the bound project.

## Failure Recovery

- Rerun `hasp agent connect pi --project-root <repo>` if the generated package
  path is missing from `pi list`.
- If `hasp_status` reports a disconnected transport or other tools are absent,
  inspect its error, re-run `hasp agent connect pi`, and verify the managed
  wrapper exists under `HASP_HOME/bin/hasp-agent-pi` and
  that `hasp agent mcp pi` can list tools from the same working tree.
- Rebind the repo if the project root changed and the daemon reports a root
  mismatch.

## Known Caveats

- Pi uses a package/extension surface rather than a native MCP config file, so
  HASP registers a generated local package instead of writing an `mcpServers`
  block.
- V1 uses daemon-issued local sessions and local process-tree protection, not
  strong same-user local isolation.
