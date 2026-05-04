# Agent Profiles

These docs describe V1 agent profile tiers.

## Support-Profile Contract

A first-class support profile is a shipped integration, not a config snippet.
It is not first-class until all of these exist:

- tested install and connection path
- recommended local configuration
- project-binding recipe
- approval UX path
- safe-inject path
- convenience `write-env` path
- release-gate regression coverage
- eval coverage for bootstrap and setup flows
- benchmark smoke coverage when the setup path changes

## Generic Broker Path

HASP also ships a generic broker path for CLI- or MCP-capable agents that are
not first-class profiles yet.

Use the generic path as the first-proof surface when you need local-first
brokered access but do not want to claim agent-specific approval UX or
release-gate coverage.

If you need subprocess-safe propagation, put `hasp mcp` behind the agent's
wrapper or launcher path.

- [Generic broker guide](./generic.md)

## Profile Tiers

| Tier | Meaning |
| --- | --- |
| First-class | Shipped integration with docs, release-gate regression coverage, eval coverage, and benchmark/smoke proof. |
| Generic-compatible | Documented first-proof broker path for agents that can invoke HASP MCP or CLI, but not enough external proof to claim first-class support. |
| Planned | Named target without shipped operator contract. |

## First-Class Profiles

Use `hasp bootstrap --profile <id> --project-root <repo>` as the compatibility bootstrap path before applying the agent-specific config example from the matching profile doc.

Bootstrap may create neutral repo aliases such as `secret_01`, but day-to-day
agent usage should prefer safe named refs such as `@OPENAI_API_KEY` with
`hasp_run` or `hasp_inject`. Agents should avoid raw reveal/get flows unless
the operator explicitly needs plaintext.

Connected agent configs also enable HASP agent-safe mode by default when the
agent is launched through a HASP wrapper or launcher. In a protected agent
workflow, `hasp secret get --reveal` and `--copy` are blocked unless the
operator first grants one-time plaintext access with `hasp session
grant-plaintext`.

For stronger subprocess coverage, launch the agent through `hasp agent launch`
or `hasp agent shell` so `HASP_AGENT_SAFE_MODE` and `HASP_SESSION_TOKEN` reach
the whole agent process tree instead of only the HASP MCP server.

- [Claude Code](./claude-code.md)
- [Cursor](./cursor.md)
- [Aider](./aider.md)
- [Codex CLI](./codex-cli.md)
- [OpenClaw](./openclaw.md)
- [Hermes](./hermes.md)

## Generic-Compatible Profiles

These profiles document a useful path, but they should not be described as
first-class until the proof contract above is satisfied with external usage
evidence.

- **generic-compatible**: first-proof broker path for any CLI- or MCP-capable
  agent that is not a first-class profile yet. Provides setup, doctor, and
  brokered proof commands without claiming agent-specific approval UX or
  release-gate coverage. See [Generic broker guide](./generic.md).

## Update Rule

When a profile changes, keep its quickstart steps, approval behavior, release
gates, and benchmark/eval expectations in sync with the canonical V1 docs.
