# Generic Broker Path

This is the first-proof surface for CLI- or MCP-capable agents that are not
first-class HASP profiles yet. Use it to prove one real repo binding and one
brokered success path without claiming agent-specific approval UX,
release-gate coverage, or benchmark proof.

## When To Use This Path

Use the generic broker path when an agent can speak stdio MCP or otherwise
invoke `hasp mcp`, but does not have a first-class HASP profile yet.

This path keeps the local-first broker model intact while giving you a clear
first brokered proof before any profile-specific support claim exists.

## Config Surface

- Canonical command: `hasp mcp`
- Generic local-first setup: `hasp setup --agent generic-compatible --repo <repo>` or
  `hasp bootstrap generic --project-root <repo>`
- Prefer the agent wrapper or launcher path when you need subprocess-safe
  propagation.

## Setup Command

Run this to initialize the vault, bind the repo, and wire the generic-compatible
MCP path in a single step:

```sh
hasp setup --agent generic-compatible --repo "<repo>" \
  --import .env --bind-imports \
  --enable-convenience-unlock=false --install-hooks=false
```

Or use the lower-level bootstrap path directly:

```sh
hasp bootstrap generic --project-root "<repo>"
```

## Doctor Command

After setup, verify the generic-compatible broker state with:

```sh
hasp bootstrap doctor --agent generic-compatible
```

or, using the bootstrap doctor subcommand with an explicit project root:

```sh
hasp bootstrap doctor generic --project-root "<repo>"
```

## First Brokered Proof

Run this command to prove the local broker works end-to-end. It exits 0 only
if the broker successfully injects the managed value into the subprocess
environment:

```sh
hasp run --project-root "<repo>" \
  --env HASP_SETUP_PROOF=<ref> \
  --grant-project window \
  --grant-secret session \
  --grant-window 15m \
  -- sh -c 'test -n "$HASP_SETUP_PROOF"'
```

Replace `<ref>` with the alias or named reference printed by setup (e.g.
`secret_01` or `@OPENAI_API_KEY`). The exact command is also printed verbatim
in the `verification.brokered_proof.command` field of the `hasp setup --json`
output.

## Ready-to-Paste Config Snippets

Use `hasp bootstrap print-config` to get a ready-to-paste MCP config snippet
for your agent:

```sh
# stdio MCP JSON (generic default)
hasp bootstrap print-config generic-compatible --format stdio-json

# Cursor / Composer mcp.json snippet
hasp bootstrap print-config generic-compatible --format cursor-json

# Codex CLI config.toml snippet
hasp bootstrap print-config generic-compatible --format codex-toml

# Claude Code .claude.json snippet
hasp bootstrap print-config generic-compatible --format claude-json
```

Each snippet embeds `"support_tier": "generic-compatible"` so the config is
clearly labeled as a generic broker path, not first-class profile support.

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

1. Initialize the local vault if needed: `hasp init`
2. Import any explicit local values you want to broker: `hasp import .env`
3. Bind the repo with `hasp bootstrap generic --project-root <repo>` and check
   the local generic-compatible broker state with `hasp bootstrap doctor generic --project-root <repo>`
4. Wire the agent to `hasp mcp` using its stdio or MCP settings, or place that
   command behind the agent wrapper or launcher if you need subprocess
   coverage
5. Use `hasp run`, `hasp_inject`, and `hasp write-env` only when the workflow
   needs brokered access

If bootstrap or binding creates a neutral repo alias such as `secret_01`, treat
that as internal plumbing. Day-to-day agent usage should prefer safe named refs
such as `@OPENAI_API_KEY` with `hasp_run` or `hasp_inject`.

## Success Signal

- `hasp bootstrap doctor generic --project-root <repo>` passes and confirms the local generic-compatible broker state
- The agent can connect to `hasp mcp`
- `hasp_list` returns only project-scoped, brokered metadata, including neutral
  aliases and named refs
- One `hasp run` or `hasp_inject` command completes against a named ref
- Brokered flows keep managed values out of agent context

## What This Does Not Prove

- first-class support for the agent
- profile-specific approval UX
- release-gate coverage
- benchmark smoke coverage

## Safe Path

- `hasp_run`
- `hasp_inject`
- Prefer named refs such as `@OPENAI_API_KEY` or `@GOOGLE_APPLICATION_CREDENTIALS` in those tool calls instead of recalling `secret_01`.
- `hasp write-env` only when explicit convenience materialization is acceptable

When HASP is connected through the shipped agent wrapper or launcher path,
agent-safe mode is enabled by default. In protected workflows,
`hasp secret get --reveal` and `--copy` are blocked unless the operator first
grants one-time plaintext access with `hasp session grant-plaintext`.

For stronger subprocess coverage, launch the agent through `hasp agent launch`
or `hasp agent shell` so `HASP_AGENT_SAFE_MODE` and `HASP_SESSION_TOKEN` reach
the whole agent process tree instead of only the HASP MCP server.

## Known Limits

- This path does not imply first-class support for the agent.
- V1 uses local, privacy-preserving process-tree protection to reduce
  accidental exposure on a normal developer machine.
- V1 does not defend against malicious same-user local processes.
- Shell exports and pasted values remain operator hygiene risks unless they are routed through explicit import or brokered materialization.
