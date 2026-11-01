# Operator guide

## Environment variables

- `HASP_HOME`
- `HASP_MASTER_PASSWORD`
- `HASP_BACKUP_PASSPHRASE`
- `HASP_TELEMETRY_DISABLED`

`HASP_TELEMETRY_DISABLED=1` is a hard runtime kill switch for optional CLI
telemetry. It prevents enabling telemetry and prevents all telemetry sends even
when prior consent exists.

## Safe local workflow

The preferred local path is:

1. import local material with `hasp import`
2. bind a repo with `hasp bootstrap` or `hasp project bind`
3. expose existing vault items that repo needs with `hasp secret expose NAME --project-root <repo>`
4. use `hasp run` or `hasp mcp`
5. use `hasp inject` for broker-owned file materialization outside the repo
6. use `hasp write-env` only when the convenience tradeoff is worth it

`hasp project bind` creates the repo boundary. It does not make every personal
vault item visible to that repo. If an agent reports that `@NAME` exists but is
not available in the project, expose that item explicitly.

## Repo guardrails

Install git hooks:

```bash
make install-hooks
```

HASP installs into Git's effective hooks directory for the current working
tree. For linked worktrees, that is the common git directory; when
`core.hooksPath` is set, HASP uses it only if it resolves inside the project or
the git common directory.

Saved hooks run before the HASP check. Pre-commit checks the resulting staged
index; pre-push gives the saved hook and the scanner separate copies of Git's
ref-update input and preserves the remote arguments. A saved-hook failure
stops the chain. Pre-push scans outgoing Git objects and rejects skipped
objects. It ignores uncommitted drafts. New refs scan the history that the
push remote's tracking refs do not already hold; deletions add no content.
Hooks that change the index later must run `hasp check-repo --staged` after
making those changes.

Reinstall existing hooks to pick up these changes. `hasp project hooks
--project-root . --install` installs the CLI hooks; `make install-hooks` installs
the repository script entry points.

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
The upgrade helper verifies the same release material and stages a new release tree before replacing the installed tree.

## Threat-model limits

- HASP reduces accidental exposure and common local leaks on a normal developer machine.
- HASP does not provide strong same-user local isolation.
- HASP does not defend against malicious same-user local processes.
- pasted values and shell exports are still operator hygiene unless you route them through explicit import or capture paths.

## Plaintext files and adapters

HASP does not create persistent plaintext sidecars by default. `hasp run` and
saved app/agent profiles can deliver file secrets through private, temporary
runtime files outside the project. The child process can read those files;
HASP removes them after execution and reports cleanup failures. This is runtime
delivery, not isolation from the child or other malicious same-user processes.

`hasp write-env` and workspace-visible adapter files are convenience
materialization. They require explicit human approval and audit, and the value
remains readable after delivery. Do not describe an exported `.env`, cookie file
or auth blob as agent-safe because it has an encrypted copy or a restrictive
file mode. Prefer brokered execution when the consumer supports it.

## Browser-session authentication

HASP does not acquire, sync or inject browser cookies, localStorage, IndexedDB
or logged-in browser profiles. It has no supported browser-session delivery
capability. A manifest may declare a value-free `browser_session` requirement;
targets cannot deliver it, and cookie/storage value fields are rejected.

The generic vault stores opaque values. It cannot determine whether an ordinary
string is a cookie or a token, and importing one does not create supported
browser integration. Do not relabel session state as ordinary configuration to
bypass manifest checks. Device-bound authentication may prevent reuse even when
a session can be copied. Browser support would need a separately designed,
locally approved capability with bounded scope, lifetime, revocation and audit.

## Consumer delivery diagnostics

`hasp doctor` reports saved app commands, missing refs, launcher permissions and
PATH, agent config file presence, target review state, and runtime temp-directory
safety. Existing rows cover hooks, audit degradation and CLI/daemon version drift.
The checks inspect metadata and files. They do not execute a consumer or grant
access. A ready command still needs the normal broker authorization at runtime.

Agent config presence does not prove that the client loads the integration.
Keychain consent is reported as `not_probed` to avoid a surprise prompt. Use
[headless setup](install.md#headless-macos-setup) when no GUI consent is possible.
`hasp project doctor` provides the detailed requirement, output and drift checks.

These extra consumer details appear only in human output. `hasp doctor --json`
keeps its existing value-free allowlist; it does not expose consumer names,
config paths, commands or vault values.
