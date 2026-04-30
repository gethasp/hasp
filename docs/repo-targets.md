# Repo requirements and targets

HASP can keep a value-free repo contract in `.hasp.manifest.json`.

The manifest answers two questions without storing secrets:

- what this repo needs
- which target should receive which subset

A target is a named workflow inside a project, such as `web.dev`,
`macos.debug`, or `deploy.production`. It is not authorization. Target expansion
still goes through the normal project binding, grant, redaction, and audit
checks.

## Manifest shape

```json
{
  "version": "v1",
  "references": [
    { "alias": "secret_01", "item": "OPENAI_API_KEY" }
  ],
  "requirements": [
    {
      "ref": "secret_01",
      "kind": "kv",
      "required": true,
      "classification": "secret"
    }
  ],
  "targets": [
    {
      "name": "web.dev",
      "root": "web",
      "command": ["npm", "run", "dev"],
      "delivery": [
        { "as": "env", "name": "OPENAI_API_KEY", "ref": "secret_01" }
      ],
      "examples": [
        { "format": "env", "path": "web/.env.example" }
      ]
    }
  ]
}
```

The file is committed. The values are not.

## Inspect requirements

Use this when a teammate needs to know which local vault items to create:

```bash
hasp project requirements --project-root .
hasp project requirements --project-root . --target web.dev --json
```

The output reports refs, kinds, target usage, and present/exposed state. It may
suggest `hasp secret add` commands, but it does not create items, approve
access, write value files, or run target commands.

## Inspect targets

```bash
hasp project targets --project-root .
hasp project doctor --project-root . --json
```

Target inspection omits command argv in agent-facing MCP listing. Project doctor
uses a dedicated safe JSON schema with diagnostic codes, refs, kinds,
classifications, and booleans only. It flags unavailable target commands, stale
examples, unignored generated outputs, workspace-visible secret delivery, kind
mismatches, and target drift without printing values or command argv.

## Generate examples

Examples are placeholder files for framework compatibility:

```bash
hasp project examples --project-root . --target web.dev --check
hasp project examples --project-root . --target web.dev --write
```

Generated examples contain placeholders such as `__HASP_SECRET__`; they never
resolve vault values. HASP writes a marker into generated examples and refuses
to overwrite stale hand-authored files silently.

## Run a target

```bash
hasp run --project-root . --target web.dev --grant-project window --grant-secret session
hasp inject --project-root . --target deploy.production -- ./deploy.sh
```

`run` and `inject` reject extra `--env` or `--file` mappings when `--target` is
used. A target does not mean "all project secrets"; it expands only the delivery
entries declared for that target.

If a target has no command, pass an override command after `--`.

## Write a generated value file

```bash
hasp write-env --project-root . --target macos.debug --grant-convenience window
```

`write-env --target` is convenience materialization. It writes a workspace-
visible file and requires explicit convenience approval. Prefer `run` or
`inject` when the tool can receive env vars or broker-owned temp files.

## Seed an app profile

```bash
hasp app connect web --project-root . --target web.dev
hasp app run web
```

`app connect --target` imports the target command and env/file mappings into a
local app profile. The profile is local state; changing the manifest later does
not silently rewrite the saved app profile.

## Drift review

HASP stores a local review record for target expansion outside git. If a target
later changes its command, refs, delivery set, or output paths, human CLI flows
warn before continuing and `hasp project doctor --json` reports `target_drift`.

## Agent and MCP surface

MCP target listing and explain are narrower than human CLI output. They return
sanitized target names, descriptions, refs, delivery kinds, destination names,
prerequisite status, and manifest identity. They do not return target command
argv or secret values.
