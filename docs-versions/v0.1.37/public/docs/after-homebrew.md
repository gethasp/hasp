# After Install

This guide is for the most common starting point:

- you already installed HASP
- you want HASP working with your coding agent today

If that is you, start with the guided setup:

```bash
hasp setup
```

`hasp setup` is the normal path after install. It can choose:

- where local encrypted HASP data lives on this machine
- machine defaults for automatic project protection
- which coding agents should be configured for MCP, or whether to skip that for now
- whether you want to add a vault secret and connect one app before setup ends
- repo binding and broker proof when you run it inside a project
- a final review step before HASP writes local changes

You should not have to manually run `hasp init`, hand-edit MCP JSON, or
bootstrap every repo before HASP is useful. Those lower-level commands still
exist for scripts, recovery, and exact control.

After machine setup, HASP can automatically adopt a project the first time you
use HASP inside it. Repo-scoped bindings still exist under the hood, but they
are created for you from machine defaults instead of requiring manual setup
first.

The rest of this page starts with the simple daily surface, then shows the
manual flow and troubleshooting fallback.

## The normal path is guided

The installed path is designed around one guided command followed by normal
work. The product model is:

- one personal vault
- connect apps once
- connect agents once
- run apps and agents normally afterward

That means the easy surface should start here:

- `hasp setup`
- `hasp secret add`
- `hasp app connect <name>`
- `hasp agent connect <profile> --project-root .`

After an app is connected, the normal run command is:

- `hasp app run <name>`

You should not need repeated command wrapping or repeated repo/bootstrap
thinking for normal work. Use the manual sections below only when you want to
inspect one layer, automate a specific step, or recover from a failed setup.

## Manual fallback and advanced control

The following sections are for scripts, recovery, exact broker testing, and
operator control. If `hasp setup` already got you to a connected app or agent,
you can skip to [what you do day to day](#8-what-you-do-day-to-day).

## 1. Confirm the install

Run:

```bash
which hasp
hasp version
```

You should see a real path and a version number.

If `hasp` is not found, restart your shell or make sure the install directory's
`bin` path is in your `PATH`.

## 2. Set your local password

HASP needs one local master password so it can open your encrypted vault.

For this shell session:

```bash
export HASP_MASTER_PASSWORD='choose-a-strong-password'
```

Optional:

```bash
export HASP_HOME="$HOME/.hasp"
```

If you do not set `HASP_HOME`, HASP uses its default local directory.

## 3. Initialize your vault

Run:

```bash
hasp init
```

That creates your local encrypted vault.

## 4. Import one real secret

The easiest path is to import an existing file.

Example `.env` file:

```bash
hasp import .env
```

Example JSON credential file:

```bash
hasp import service-account.json
```

If you want the direct terminal path, use:

```bash
hasp secret add
```

If you already have a secret file or shell snippet, the import path still
works:

```bash
printf 'export OPENAI_API_KEY=your-real-key\n' | hasp import --preview --format env -
printf 'export OPENAI_API_KEY=your-real-key\n' | hasp import --format env -
```

That is safer than leaving it in shell history or dropping it into a repo file.

## 5. Bind one repo

Go into one repo you use with an agent:

```bash
cd /path/to/your/repo
```

Now bind a safe alias to one imported secret:

```bash
hasp bootstrap \
  --profile codex-cli \
  --project-root "$PWD" \
  --alias secret_01=OPENAI_API_KEY
```

What that means:

- `OPENAI_API_KEY` is the real imported secret name in the vault
- `secret_01` is the safe alias you expose to the repo and agent workflow
- `codex-cli` picks the first-class integration defaults for Codex CLI

If you are using a different first-class agent, swap the profile:

- `claude-code`
- `cursor`
- `aider`
- `codex-cli`

Generic-compatible profiles are also available when they match your agent, but
they are not first-class support claims yet:

- `openclaw`
- `hermes`

If you just want to save a secret and make it available in the current repo,
the simpler path is:

```bash
cd /path/to/your/repo
hasp secret add
```

If your agent is not first-class, use:

```bash
hasp bootstrap generic --project-root "$PWD" --hooks=false
hasp bootstrap doctor generic --project-root "$PWD"
```

## 6. Test the broker before touching your agent

Run one brokered command first:

```bash
hasp run \
  --project-root "$PWD" \
  --env OPENAI_API_KEY=secret_01 \
  --grant-project window \
  --grant-secret session \
  --grant-window 15m \
  -- sh -c 'test -n "$OPENAI_API_KEY"'
```

If that succeeds, HASP is working.

What the flags mean:

- `--env OPENAI_API_KEY=secret_01`
  Put the secret bound to `secret_01` into the command as `OPENAI_API_KEY`
- `--grant-project window`
  Reuse approval for this project for a time window
- `--grant-secret session`
  Reuse approval for this secret in the current session
- `--grant-window 15m`
  Keep that project approval open for 15 minutes

## 7. Connect your coding agent

For first-class agents, the common pattern is the same:

- HASP runs as a local stdio MCP server
- the command is `hasp mcp`

Generic MCP config shape:

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

Use the matching profile doc for your agent:

- [Codex CLI](./agent-profiles/codex-cli.md)
- [Claude Code](./agent-profiles/claude-code.md)
- [Cursor](./agent-profiles/cursor.md)
- [Aider](./agent-profiles/aider.md)

Generic-compatible profile docs:

- [OpenClaw](./agent-profiles/openclaw.md)
- [Hermes](./agent-profiles/hermes.md)

Before opening your agent, test the MCP server directly:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp
```

If you see the HASP tools, your agent should be able to connect.

## 8. What you do day to day

Start with saved app and agent profiles. You should not need to rebuild the
long broker command for normal work.

### Easy path

Run a connected app:

```bash
hasp app run <name>
```

Add another secret:

```bash
hasp secret add
```

Connect another app when you need one:

```bash
hasp app connect <name>
```

Connect or refresh an agent profile in the current repo:

```bash
hasp agent connect <profile> --project-root .
```

Review activity:

```bash
hasp audit
```

### Advanced: one-off command delivery

Use `hasp run` when you do not have a saved app profile yet or when a script
needs an exact one-off mapping:

```bash
hasp run \
  --project-root "$PWD" \
  --env OPENAI_API_KEY=secret_01 \
  --grant-project window \
  --grant-secret session \
  --grant-window 15m \
  -- your-command
```

Prefer the easy app/agent commands when they fit. Use this broker form when
you need to spell out the project, env mapping, and grant window yourself.

### Advanced: materialize a file only when a tool needs one

```bash
hasp write-env \
  --project-root "$PWD" \
  --output "$PWD/.env.local" \
  --env OPENAI_API_KEY=secret_01 \
  --grant-project window \
  --grant-secret session \
  --grant-convenience window
```

Use this only when a tool absolutely requires a real file.

This is convenience mode, not the safest path.

## 9. Backup your vault

Do this before you get comfortable.

```bash
export HASP_BACKUP_PASSPHRASE='choose-a-recovery-passphrase'
hasp export-backup --output ./hasp.backup.json
```

If you ever need to restore:

```bash
export HASP_MASTER_PASSWORD='new-master-password'
export HASP_BACKUP_PASSPHRASE='choose-a-recovery-passphrase'
hasp restore-backup --input ./hasp.backup.json
```

## 10. What not to expect

HASP helps a lot, but do not expect magic.

- It reduces common local leaks.
- It does not protect you from a malicious same-user local process.
- It does not make pasted secrets magically safe after the fact.
- `write-env` is explicit convenience. Once HASP writes a real file, the OS,
  editors, backups, and git hooks can all see it.

## 11. If something is broken

### `hasp` says it needs a master password

Set:

```bash
export HASP_MASTER_PASSWORD='your-password'
```

### Your agent cannot connect to HASP

Test:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp
```

If that fails, fix HASP first before debugging the agent.

### Your repo moved or changed paths

Run bootstrap again in the new repo root:

```bash
hasp bootstrap --profile codex-cli --project-root "$PWD" --alias secret_01=OPENAI_API_KEY
```

### A command keeps prompting too often

Use a project window:

```bash
--grant-project window --grant-window 15m
```

### You are not sure what profile to use

Start with:

- your real agent profile if it is listed
- `generic` if it is not

## 12. The shortest successful setup

The easiest successful path is guided:

```bash
hasp setup
cd /path/to/repo
hasp secret add
hasp app connect <name>
hasp agent connect <profile> --project-root .
hasp app run <name>
```

If those commands work, you are ready to use HASP through your connected app
or coding agent.

If you need a fully explicit scriptable proof instead, use the advanced form:

```bash
export HASP_MASTER_PASSWORD='choose-a-strong-password'
hasp init
printf 'export OPENAI_API_KEY=your-real-key\n' | hasp import --format env -
cd /path/to/repo
hasp bootstrap --profile codex-cli --project-root "$PWD" --alias secret_01=OPENAI_API_KEY
hasp run --project-root "$PWD" --env OPENAI_API_KEY=secret_01 --grant-project window --grant-secret session --grant-window 15m -- sh -c 'test -n "$OPENAI_API_KEY"'
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp
```

Use this form for automation, recovery, or debugging a specific lower-level
layer.
