# Generic Broker Path

## When To Use This Path

Use the generic broker path when an agent can speak stdio MCP or otherwise invoke `hasp mcp`, but does not have a first-class HASP profile yet.

This path keeps the local-first broker model intact without claiming profile-specific approval UX, release-gate coverage, or benchmark proof for that agent.

## Config Surface

- Canonical command: `hasp mcp`
- Generic local-first setup: `hasp bootstrap generic --project-root <repo>` or `hasp init`, `hasp import`, then point the agent at the stdio command

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
3. Optionally use `hasp bootstrap generic --project-root <repo>` to bind the repo and print the generic-path metadata
4. Wire the agent to `hasp mcp` using its stdio or MCP settings
5. Use `hasp run`, `hasp_inject`, and `hasp write-env` only when the workflow needs brokered access

## Success Signal

- The agent can connect to `hasp mcp`
- `hasp_list` returns only project-scoped, brokered metadata
- Brokered flows keep managed values out of agent context

## Safe Path

- `hasp_run`
- `hasp_inject`
- `hasp write-env` only when explicit convenience materialization is acceptable

## Known Limits

- This path does not imply first-class support for the agent.
- V1 reduces accidental exposure and common local leaks on a normal developer machine.
- V1 does not defend against malicious same-user local processes.
- Shell exports and pasted values remain operator hygiene risks unless they are routed through explicit import or brokered materialization.
