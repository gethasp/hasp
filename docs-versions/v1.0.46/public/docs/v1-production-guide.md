# V1 production guide

## What V1 can prove today

V1 is ready for a real developer-machine pilot.

You can test:

- local install on macOS or Linux
- local vault initialization
- import from `.env` and JSON credential files
- interactive `hasp secret add`
- connected app consumers through `hasp app connect`, `run`, `install`, `shell`, `disconnect`, and `list`
- connected agent consumers through `hasp agent connect`, `disconnect`, and `list`
- brokered `run` and safe `inject`
- explicit convenience `write-env`
- repo guardrails, audit, and `export-backup`/`restore-backup`
- first-class profile bootstrap for the shipped first-class agent set
- generic broker compatibility for other CLI- or MCP-capable agents

This guide is for one developer machine and one real repo. It is not a cloud rollout guide.

## Surface Today

The current build supports both:

- consumer-first setup through `hasp secret add`, `hasp app ...`, and `hasp agent ...`
- lower-level broker primitives such as `run`, `inject`, and `write-env`

`hasp setup` no longer assumes you are here for an agent. You can use it for
machine-only setup, skip agent config for now, or continue into adding a vault
secret and connecting one app in the same interactive flow.

## Installation path

Use either:

- `make build`
- a published packaged release from GitHub Releases
- the optional `https://downloads.gethasp.com/hasp/releases/<tag>/` mirror when
  that mirror is configured for the same release bytes

## Pilot checklist

1. Install from the release artifact, not only from source.
2. Initialize a fresh vault.
3. Import one `.env` file and one JSON credential file.
4. Bind one real repo.
5. Run one brokered command that needs a secret.
6. Write one convenience env file and confirm the warning path is clear.
7. Trigger `check-repo` on a managed value inside the repo and confirm the default block.
8. Run `hasp export-backup` to write an encrypted vault backup.
9. Run `hasp restore-backup` into a second HASP home and confirm the restored vault opens.
10. Point one first-class agent at `hasp mcp`.
11. Point one generic MCP-capable client at the generic path.

## Known limits

- V1 is local-first. There is no hosted control plane.
- V1 does not give you strong same-user local isolation.
- V1 does not manage your PATH for you.
- app launchers still require explicit consent. In interactive `hasp app connect`, HASP asks before it creates one and, when needed, asks before it patches shell PATH. In scripts, use `--install=always|never|ask` and `--add-to-path=always|never|ask` (`true`/`false` are accepted as aliases for `always`/`never`). Launchers are written under `HASP_HOME/bin`.
- V1 treats pasted values and shell exports as operator hygiene unless you route them through explicit import or capture paths.
