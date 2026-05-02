# Reading HASP error messages

HASP errors have two stable layers:

- an exit bucket from `0` through `6`
- an error code such as `E_NOT_FOUND` when the command runs with `--json`

Use the code when you need precise automation. Use the exit bucket when a
script only needs to know the broad class of failure.

## The error envelope

Plain commands print a human message on stderr:

```bash
hasp secret show MISSING
```

JSON commands print one machine-readable error envelope on stderr:

```bash
hasp secret show MISSING --json 2>err.json
```

Shape:

```json
{"error":{"code":"E_NOT_FOUND","message":"secret missing","hint":"run hasp secret list"}}
```

Fields:

- `code`: stable machine-readable error code
- `message`: human-readable context for this exact failure
- `hint`: optional next action when HASP can give one safely

Read an error in this order:

1. `code`
2. exit bucket
3. `hint`
4. `message`

Do not parse the English message in scripts. It is allowed to get clearer over
time.

## Exit buckets

| Exit | Bucket | Codes |
| --- | --- | --- |
| `0` | ok | command succeeded |
| `1` | generic / internal | `E_INTERNAL` or an uncategorized failure |
| `2` | user input | `E_USER_INPUT`, `E_NOT_IN_REPO` |
| `3` | permission | `E_PERMISSION`, `E_GRANT_DENIED`, `E_VAULT_LOCKED`, `E_PASSWORD_WRONG` |
| `4` | daemon / I/O | `E_DAEMON_UNREACHABLE` |
| `5` | leak detected | `E_REPO_LEAK` |
| `6` | not found | `E_NOT_FOUND` |

## Error codes

### `E_INTERNAL`

Exit bucket: `1`.

HASP could not classify the failure more specifically. This is the fallback for
unexpected runtime failures and plain Go errors that do not match a known
category.

Common triggers:

- an unexpected local runtime failure
- a current-user lookup failure during runtime setup
- an error path that has not yet been wrapped with a more specific HASP code

What to do:

- run the smallest command that reproduces the failure
- run `hasp doctor`
- include `hasp version`, the command, and the JSON error envelope when filing
  a bug

### `E_USER_INPUT`

Exit bucket: `2`.

The command shape is wrong or HASP needs different input before it can safely
continue.

Common triggers:

- unknown command
- unsupported flag
- missing required argument or flag
- invalid flag value
- malformed command grammar
- a refusal to overwrite an existing file
- a broker reference that is not exposed to the current repo

What to do:

- run `hasp help <topic>` for the command you were trying to use
- check spelling, flags, and required values
- if the hint says a reference is not exposed, run
  `hasp secret expose --project-root . <NAME>` or create it with
  `hasp secret add <NAME>`
- prefer `hasp setup` when you are trying to do first-run configuration

### `E_NOT_IN_REPO`

Exit bucket: `2`.

The command needs repository context and HASP could not determine one.

Common triggers:

- running a repo-scoped command outside a git checkout
- omitting `--project-root` for a command that needs a project
- using a path that no longer points at the intended repo

What to do:

- `cd` into the repo and retry
- pass `--project-root /path/to/repo`
- run `hasp setup` or `hasp project bind --project-root /path/to/repo`

Some older or generic paths may classify the text "not in a git repository" as
`E_USER_INPUT`. Treat both codes as exit bucket `2` and fix the repo context.

### `E_PERMISSION`

Exit bucket: `3`.

HASP refused access for a permission reason, but the failure was not specific
enough to use `E_GRANT_DENIED`, `E_VAULT_LOCKED`, or `E_PASSWORD_WRONG`.

Common triggers:

- a permission check fails before a more specific category is available
- a future broker or platform permission path reports a generic denial

What to do:

- read the `hint` when one is present
- verify the vault is unlocked
- verify the project is bound
- retry with an explicit grant scope only when the action is intentional

### `E_GRANT_DENIED`

Exit bucket: `3`.

HASP found the requested project or secret path, but the current session does
not have the grant needed to deliver the value.

Common triggers:

- a project lease is required for `hasp run` or `hasp inject`
- a secret grant is missing, expired, or denied
- a repo has not been bound before a brokered operation

What to do:

- run `hasp setup` inside the repo for the guided path
- bind explicitly with `hasp project bind --project-root <dir>`
- grant explicitly with `hasp session grant --project <id>`
- for command delivery, pass intentional grant flags such as
  `--grant-project window` and `--grant-secret session`

### `E_VAULT_LOCKED`

Exit bucket: `3`.

HASP could not open the encrypted local vault.

Common triggers:

- first run has not initialized the vault
- `HASP_MASTER_PASSWORD` is not set in a non-interactive shell
- the process cannot prompt for the master password

What to do:

- run `hasp setup`
- for scripted use, set `HASP_MASTER_PASSWORD`
- if you are building the vault manually, run `hasp init`

When this code is produced from the vault-not-initialized path, the hint is:

```text
run hasp setup or set HASP_MASTER_PASSWORD
```

### `E_PASSWORD_WRONG`

Exit bucket: `3`.

The password was present, but it did not unlock the vault.

Common triggers:

- typo in an interactive password prompt
- stale `HASP_MASTER_PASSWORD` in the shell
- using a password from a different local vault or restored backup

What to do:

- retry with the correct local master password
- clear or replace `HASP_MASTER_PASSWORD` if the shell value is stale
- if the vault was replaced, restore the matching backup or initialize a new
  vault intentionally

### `E_DAEMON_UNREACHABLE`

Exit bucket: `4`.

HASP expected to reach the local daemon or broker path and could not.

Common triggers:

- the daemon is not running
- a local socket is stale
- a connection is refused
- a daemon request times out or reports unreachable

What to do:

- run `hasp doctor`
- restart the daemon or the app that owns the broker connection
- retry the command after the local runtime is healthy

The generic classifier maps daemon messages containing phrases such as
`not reachable`, `unreachable`, `connection refused`, or `dial unix` to this
code.

### `E_REPO_LEAK`

Exit bucket: `5`.

`hasp check-repo` found managed secret values in repository files.

Common triggers:

- a real secret was written into `.env`, `.env.local`, logs, fixtures, or
  generated output
- a previous manual copy or reveal left plaintext in the working tree
- a support bundle or release artifact includes a managed value

What to do:

- remove the plaintext from the repo file
- rotate the secret if it was committed, shared, or uploaded
- rerun `hasp check-repo --project-root .`
- use `--allow-managed-secrets` only when the override is intentional and
  reviewed

When this code blocks a repo scan, the hint is:

```text
re-run with --allow-managed-secrets if the override is intentional
```

### `E_NOT_FOUND`

Exit bucket: `6`.

The named object is not in the vault or local HASP metadata.

Common triggers:

- secret name does not exist
- binding, grant, or reference was removed
- a script uses a name from another machine, backup, or repo
- a repo-visible reference points at a missing vault item

What to do:

- run `hasp secret list`
- check the exact name and case
- create the secret with `hasp secret add <NAME>`
- expose it to the repo with `hasp secret expose --project-root . <NAME>`
- if this started after cleanup, update scripts to use a current reference

## Script examples

Branch on the exit bucket when that is enough:

```bash
hasp secret show "$NAME" >/dev/null
case $? in
  0) echo "ok" ;;
  6) echo "not found" ;;
  3) echo "permission problem" ;;
  *) echo "other hasp failure" ;;
esac
```

Branch on the structured code when you need precision:

```bash
if ! hasp secret show "$NAME" --json >/tmp/hasp.out 2>/tmp/hasp.err; then
  code="$(jq -r '.error.code // "E_INTERNAL"' /tmp/hasp.err)"
  case "$code" in
    E_NOT_FOUND) hasp secret add "$NAME" ;;
    E_VAULT_LOCKED) hasp setup ;;
    E_REPO_LEAK) hasp check-repo --project-root . ;;
    *) cat /tmp/hasp.err >&2; exit 1 ;;
  esac
fi
```
