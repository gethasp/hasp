# Operator guide

## Environment variables

- `HASP_HOME`
- `HASP_MASTER_PASSWORD`
- `HASP_BACKUP_PASSPHRASE`

## Safe local workflow

The preferred local path is:

1. import local material with `hasp import`
2. bind a repo with `hasp bootstrap` or `hasp project bind`
3. use `hasp run` or `hasp mcp`
4. use `hasp inject` for broker-owned file materialization outside the repo
5. use `hasp write-env` only when the convenience tradeoff is worth it

## Repo guardrails

Install git hooks:

```bash
make install-hooks
```

Manual repo scan:

```bash
bin/hasp check-repo --project-root /path/to/repo
```

Audited override:

```bash
bin/hasp check-repo --project-root /path/to/repo --allow-managed-secrets
```

## Release trust path

Verify a packaged release before install:

```bash
scripts/hasp-verify-release.sh hasp_<version>_<os>_<arch>.tar.gz
scripts/hasp-install-release.sh --verify hasp_<version>_<os>_<arch>.tar.gz
```

The packaged installer verifies the signed checksum manifest, the tarball
signature, and the packaged binary signature before it stages the install tree.

## Threat-model limits

- HASP reduces accidental exposure and common local leaks on a normal developer machine.
- HASP does not provide strong same-user local isolation.
- HASP does not defend against malicious same-user local processes.
- pasted values and shell exports are still operator hygiene unless you route them through explicit import or capture paths.
