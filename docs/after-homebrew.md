# I installed HASP with Homebrew. Now what?

This guide is for the most common starting point:

- you already ran `brew tap gethasp/homebrew-tap`
- you already ran `brew install hasp`
- you want HASP working with your coding agent today

If that is you, follow these steps in order.

If you want the simple path first, start with:

```bash
hasp setup
```

That guided flow now walks through:

- where local encrypted HASP data lives on this machine
- machine defaults for automatic project protection
- which coding agents should be configured for MCP
- a final review step before HASP writes local changes

You do not have to manually onboard every repo up front anymore.

After machine setup, HASP can automatically adopt a project the first time you
use HASP inside it. Repo-scoped bindings still exist under the hood, but they
are created for you from machine defaults instead of requiring manual setup
first.

The rest of this page is the manual flow and the troubleshooting fallback.

## 1. Confirm the install

Run:

```bash
which hasp
hasp version
```

You should see a real path and a version number.

If `hasp` is not found, restart your shell or make sure Homebrew's `bin` path is in your `PATH`.

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

If you only have one pasted secret right now, use the explicit import path:

```bash
printf 'export OPENAI_API_KEY=your-real-key\n' | hasp import --preview --format env -
printf 'export OPENAI_API_KEY=your-real-key\n' | hasp import --format env -
```

That is safer than leaving it in shell history or dropping it into a repo file.

## 5. Bind one repo

Go into one repo you actually use with an agent:

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
- `openclaw`
- `hermes`

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
- [OpenClaw](./agent-profiles/openclaw.md)
- [Hermes](./agent-profiles/hermes.md)

Before opening your agent, test the MCP server directly:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp
```

If you see the HASP tools, your agent should be able to connect.

## 8. What you actually do day to day

You usually need only three commands.

### A. Run a command with a secret

```bash
hasp run \
  --project-root "$PWD" \
  --env OPENAI_API_KEY=secret_01 \
  --grant-project window \
  --grant-secret session \
  --grant-window 15m \
  -- your-command
```

Use this whenever you can.

### B. Materialize a file only when you really need to

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

### C. Check what HASP has been doing

```bash
hasp audit
```

Use that if you want to review imports, approvals, backup/restore events, and similar actions.

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
- `write-env` is explicit convenience. Once you write a real file, that file is a real file.

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

If you want the absolute minimum happy path, this is it:

```bash
export HASP_MASTER_PASSWORD='choose-a-strong-password'
hasp init
printf 'export OPENAI_API_KEY=your-real-key\n' | hasp import --format env -
cd /path/to/repo
hasp bootstrap --profile codex-cli --project-root "$PWD" --alias secret_01=OPENAI_API_KEY
hasp run --project-root "$PWD" --env OPENAI_API_KEY=secret_01 --grant-project window --grant-secret session --grant-window 15m -- sh -c 'test -n "$OPENAI_API_KEY"'
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp
```

If those commands work, you are ready to connect your coding agent.
