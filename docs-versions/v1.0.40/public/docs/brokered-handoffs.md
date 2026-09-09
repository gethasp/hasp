# Brokered handoffs

Keep secret expansion inside the command HASP starts. `hasp run` supplies an
environment value; `hasp inject --file` supplies a temporary file path. Both
redact managed values from captured child output. Neither prevents the child
from writing a file or sending a value to an endpoint you selected.

## Send a value through SSH stdin

The remote command must accept its input on stdin. Use a fixed, reviewed
command and an SSH destination you have verified:

```bash
hasp inject --project-root . --grant-project session \
  --env TOKEN=@DEPLOY_TOKEN --file SSH_KEY=@DEPLOY_KEY -- \
  sh -c 'printf "%s" "$TOKEN" | ssh -T -i "$SSH_KEY" deploy@example.com /usr/local/bin/consume-deploy-token'
```

`DEPLOY_KEY` must be a file-kind item exposed to this project. Secret policies
that require a grant also need `--grant-secret once` or another permitted
scope. The outer single quotes defer `$TOKEN` and `$SSH_KEY` expansion until
the brokered shell runs. There is no `secret reveal` or plaintext command
substitution in the caller.

OpenSSH's [`-T` option](https://man.openbsd.org/ssh) disables pseudo-terminal
allocation. Do not use `-n`, which disconnects stdin, for this handoff. Keep
host-key verification enabled. SSH constructs a remote shell command from its
trailing arguments; do not interpolate secrets or untrusted text into that
command string.

For a file-kind value that the remote tool reads from stdin, put `cat
"$CREDENTIAL_PATH"` on the left of the pipe instead:

```bash
hasp inject --project-root . --grant-project session \
  --file CREDENTIAL_PATH=@SERVICE_CREDENTIAL --file SSH_KEY=@DEPLOY_KEY -- \
  sh -c 'cat "$CREDENTIAL_PATH" | ssh -T -i "$SSH_KEY" deploy@example.com /usr/local/bin/consume-service-credential'
```

## A remote tool that requires a file

Install and review the remote consumer separately. It can read stdin into a
private temporary file, run the tool, and remove the file when the shell exits:

```sh
#!/bin/sh
set -eu
umask 077
credential=$(mktemp)
trap 'rm -f "$credential"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cat > "$credential"
your-tool --credential-file "$credential"
```

Replace `your-tool` with the reviewed consumer. The trap handles ordinary
success, failure, and the listed catchable signals. It cannot run after
`SIGKILL`, a machine failure, or an abrupt termination that does not reach the
shell. HASP removes its local files; it cannot guarantee remote cleanup. Keep
remote creation, use, and cleanup in one invocation, and arrange remote
recovery for abandoned files when needed.

## Temporary paths expire after each run

HASP creates local injection files outside the repository with mode `0600` in
a private run directory. The runner removes that directory when the command
ends, including a nonzero exit. A cleanup failure returns an error with the
remaining directory and the command's outcome. Inspect both before retrying:
the command may already have changed the remote system.

A consumer that saves a credential path in persistent configuration will
retain an unusable path after the run. Save the HASP reference in an app
profile, then configure and use the consumer within each brokered invocation:

```bash
hasp app connect service-task --project-root . --install=never \
  --cmd './scripts/service-task.sh' --file CREDENTIAL_PATH=SERVICE_CREDENTIAL
hasp app run service-task
```

`service-task.sh` must read the current `$CREDENTIAL_PATH`, configure the tool
if required, and finish using the file before it exits. Each `app run`
creates a fresh path. A detached service that needs the file after its launcher
exits needs a different lifecycle; the launcher cannot make this temporary
path durable. Never commit the injected file or copy it into agent output.
