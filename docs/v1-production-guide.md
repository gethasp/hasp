# V1 production guide

## What V1 can prove today

V1 is ready for a real developer-machine pilot.

You can test:

- local install on macOS or Linux
- local vault initialization
- import from `.env` and JSON credential files
- brokered `run` and safe `inject`
- explicit convenience `write-env`
- repo guardrails, audit, and backup/restore
- first-class profile bootstrap for the shipped agent set
- generic broker compatibility for other CLI- or MCP-capable agents

This guide is for one developer machine and one real repo. It is not a cloud rollout guide.

## Installation path

Use either:

- `make build`
- a published packaged release from `https://downloads.gethasp.com/hasp/releases/<tag>/`

## Pilot checklist

1. Install from the release artifact, not only from source.
2. Initialize a fresh vault.
3. Import one `.env` file and one JSON credential file.
4. Bind one real repo.
5. Run one brokered command that needs a secret.
6. Write one convenience env file and confirm the warning path is clear.
7. Trigger `check-repo` on a managed value inside the repo and confirm the default block.
8. Export a backup.
9. Restore into a second HASP home and confirm the restored vault opens.
10. Point one first-class agent at `hasp mcp`.
11. Point one generic MCP-capable client at the generic path.

## Known limits

- V1 is local-first. There is no hosted control plane.
- V1 does not give you strong same-user local isolation.
- V1 does not manage your PATH for you.
- V1 treats pasted values and shell exports as operator hygiene unless you route them through explicit import or capture paths.
