# Agent Profiles

These docs describe the V1 support profiles that HASP claims as first-class.

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

HASP also ships a generic broker path for CLI- or MCP-capable agents that are not first-class profiles yet.

Use the generic path when you only need local-first brokered access and do not want to claim agent-specific approval UX or release-gate coverage.

- [Generic broker guide](./generic.md)

## Current Profiles

Use `hasp bootstrap --profile <id> --project-root <repo>` as the common local-first setup path before applying the agent-specific config example from the matching profile doc.

- [Claude Code](./claude-code.md)
- [Cursor](./cursor.md)
- [Aider](./aider.md)
- [Codex CLI](./codex-cli.md)
- [OpenClaw](./openclaw.md)
- [Hermes](./hermes.md)

## Update Rule

When a profile changes, keep its quickstart steps, approval behavior, release
gates, and benchmark/eval expectations in sync with the canonical V1 docs.
