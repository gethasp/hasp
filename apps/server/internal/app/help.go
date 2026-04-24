package app

import (
	"fmt"
	"io"
	"strings"
)

type helpTopicSpec struct {
	key  string
	text string
}

var helpTopicInventory = []helpTopicSpec{
	{key: "init", text: initHelpText},
	{key: "setup", text: setupHelpText},
	{key: "bootstrap", text: bootstrapHelpText},
	{key: "doctor", text: doctorHelpText},
	{key: "import", text: importHelpText},
	{key: "set", text: setHelpText},
	{key: "capture", text: captureHelpText},
	{key: "secret", text: secretHelpText},
	{key: "secret add", text: secretAddHelpText},
	{key: "secret update", text: secretUpdateHelpText},
	{key: "secret rotate", text: secretRotateHelpText},
	{key: "secret delete", text: secretDeleteHelpText},
	{key: "secret get", text: secretGetHelpText},
	{key: "secret retrieve", text: secretGetHelpText},
	{key: "secret list", text: secretListHelpText},
	{key: "secret expose", text: secretExposeHelpText},
	{key: "secret hide", text: secretHideHelpText},
	{key: "app", text: appHelpText},
	{key: "app connect", text: appConnectHelpText},
	{key: "app run", text: appRunHelpText},
	{key: "app install", text: appInstallHelpText},
	{key: "app shell", text: appShellHelpText},
	{key: "app disconnect", text: appDisconnectHelpText},
	{key: "app list", text: appListHelpText},
	{key: "agent", text: agentHelpText},
	{key: "agent connect", text: agentConnectHelpText},
	{key: "agent mcp", text: agentMCPHelpText},
	{key: "agent launch", text: agentLaunchHelpText},
	{key: "agent shell", text: agentShellHelpText},
	{key: "agent disconnect", text: agentDisconnectHelpText},
	{key: "agent list", text: agentListHelpText},
	{key: "agent list-supported", text: agentListSupportedHelpText},
	{key: "project", text: projectHelpText},
	{key: "run", text: runHelpText},
	{key: "inject", text: injectHelpText},
	{key: "write-env", text: writeEnvHelpText},
	{key: "check-repo", text: checkRepoHelpText},
	{key: "daemon", text: daemonHelpText},
	{key: "session", text: sessionHelpText},
	{key: "session grant-plaintext", text: sessionGrantPlaintextHelpText},
	{key: "vault", text: vaultHelpText},
	{key: "vault lock", text: vaultLockHelpText},
	{key: "status", text: statusHelpText},
	{key: "ping", text: pingHelpText},
	{key: "audit", text: auditHelpText},
	{key: "export-backup", text: exportBackupHelpText},
	{key: "restore-backup", text: restoreBackupHelpText},
	{key: "mcp", text: mcpHelpText},
	{key: "tui", text: tuiHelpText},
	{key: "version", text: versionHelpText},
}

var helpTopicByKey = func() map[string]string {
	values := make(map[string]string, len(helpTopicInventory))
	for _, spec := range helpTopicInventory {
		values[spec.key] = spec.text
	}
	return values
}()

func isHelpArg(value string) bool {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "help", "-h", "--help":
		return true
	default:
		return false
	}
}

func printHelpTopic(w io.Writer, args []string) error {
	key := strings.Join(normalizeHelpArgs(args), " ")
	if key == "" {
		_, err := io.WriteString(w, renderRootHelpText())
		return err
	}
	text, ok := helpTopicByKey[key]
	if !ok {
		return fmt.Errorf("unknown help topic %q", key)
	}
	_, err := io.WriteString(w, text)
	return err
}

func normalizeHelpArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if isHelpArg(arg) {
			continue
		}
		value := strings.TrimSpace(strings.ToLower(arg))
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

func printHelp(w io.Writer) {
	_ = printHelpTopic(w, nil)
}

const rootHelpPrelude = `hasp keeps secrets in one local vault and delivers them to apps, agents, and repo-scoped commands without leaving raw values in source control.

Core concepts
  vault    encrypted local store under HASP_HOME
  secret   named item in the vault
  app      reusable profile for a normal application
  agent    one-time local integration for a coding agent
  project  repo-scoped boundary, alias map, and guardrail set
  broker   runtime that grants short-lived access for repo work

Start here
  hasp setup
  hasp help setup
  hasp help app connect
  hasp help agent connect
`

const rootHelpTopicsSection = `Help topics
  hasp help secret
  hasp help secret add
  hasp help app
  hasp help app connect
  hasp help agent
  hasp help agent list-supported
  hasp help doctor
  hasp help agent shell
  hasp help project
  hasp help run
  hasp help setup

Output
  add --json to structured status and mutation commands for machine-readable output
`

func renderRootHelpText() string {
	var builder strings.Builder
	builder.WriteString(rootHelpPrelude)
	writeRootHelpCommandSection(&builder, "Daily commands", rootCommandsByGroup(commandGroupDaily))
	builder.WriteString("\n")
	writeRootHelpCommandSection(&builder, "Utility commands", rootCommandsByGroup(commandGroupUtility))
	builder.WriteString("\n")
	builder.WriteString(rootHelpTopicsSection)
	return builder.String()
}

func writeRootHelpCommandSection(builder *strings.Builder, title string, commands []rootCommandSpec) {
	builder.WriteString(title)
	builder.WriteString("\n")
	for _, command := range commands {
		_, _ = fmt.Fprintf(builder, "  %-17s %s\n", command.name, command.summary)
	}
}

const initHelpText = `hasp init

Create the local encrypted vault under HASP_HOME.

Use this once per machine or once per HASP_HOME.

Examples
  hasp init
`

const setupHelpText = `hasp setup

Guide a user through machine setup. This command can choose the HASP home,
optionally bind one repo, optionally skip agent setup, and in interactive use
continue into adding secrets or connecting an app.

Use setup when you want one guided flow. Use the lower-level commands when you
already know the exact state you want.

Examples
  hasp setup
  hasp setup --non-interactive --hasp-home ~/.hasp --repo . --agent claude-code
`

const bootstrapHelpText = `hasp bootstrap

Configure a repo and an agent profile in one operator-focused flow. Bootstrap
exists for repo-first workflows. The newer consumer-first path is usually:

  hasp secret add
  hasp agent connect claude-code --project-root .

Examples
  hasp bootstrap --profile claude-code --project-root .
  hasp bootstrap generic --project-root .
  hasp bootstrap doctor --profile claude-code --project-root .
`

const doctorHelpText = `hasp doctor

Diagnose local HASP health without exposing secrets or reconnaissance-heavy
details in JSON mode.

JSON output is intentionally allowlisted to daemon, vault, binding, hooks,
audit-degraded, and version-number fields.

Examples
  hasp doctor
  hasp doctor --json
`

const importHelpText = `hasp import

Import secrets from a .env file or a JSON credential file.

Use import when you already have secrets on disk and want to move them into the
vault. Use secret add when you want to enter values directly.

Examples
  hasp import .env
  hasp import service-account.json
  hasp import --project-root . --bind .env
`

const setHelpText = `hasp set

Add or replace one secret without an interactive prompt.

Use set in scripts and tests. Use secret add when a human is at the terminal.

Examples
  hasp set --name OPENAI_API_KEY --value sk-123
  hasp set --name CERT_FILE --kind file --from-file cert.pem
`

const captureHelpText = `hasp capture

Save a value into the vault and optionally bind it to a repo while you already
have a live broker session.

Use capture for repair and recovery paths. It is not the normal first-run path.

Examples
  hasp capture --name api_token --value abc123
  hasp capture --name api_token --value abc123 --project-root . --bind
`

const secretHelpText = `hasp secret

Work with the one local vault. These commands do not create new vaults per repo
or per app.

Subcommands
  add        add one or more secrets
  update     replace existing secret values
  rotate     replace a value for incident response and revoke grants
  delete     remove secrets from the vault
  get        retrieve a secret value
  list       list secret names and metadata
  expose     bind a secret to a repo boundary and create a reference
  hide       remove one repo exposure for a secret

Learn more
  hasp help secret add
  hasp help secret expose
`

const secretAddHelpText = `hasp secret add

Add one or more secrets to the vault. In a repo, HASP can also expose the new
secret to that repo boundary unless you say vault-only.

Use this as the main human path.

Examples
  hasp secret add
  hasp secret add OPENAI_API_KEY
  hasp secret add --vault-only
`

const secretUpdateHelpText = `hasp secret update

Replace the value for one or more existing secrets.

Examples
  hasp secret update OPENAI_API_KEY
  hasp secret update
`

const secretRotateHelpText = `hasp secret rotate

Replace a local HASP secret value for incident response and invalidate active
grants for that local item. Provider-side credential rotation remains the
operator's responsibility.

Examples
  hasp secret rotate OPENAI_API_KEY
  hasp secret rotate OPENAI_API_KEY=new-local-value
`

const secretDeleteHelpText = `hasp secret delete

Delete one or more secrets from the vault. HASP asks for confirmation unless
you pass --yes.

Examples
  hasp secret delete OPENAI_API_KEY
  hasp secret delete --yes OPENAI_API_KEY
`

const secretGetHelpText = `hasp secret get

Retrieve a secret value only when you explicitly reveal or copy it. By default
this command shows secret metadata. Agents should use named refs with the MCP
broker path instead of raw get or reveal.

When agent-safe mode is active, HASP blocks --reveal and --copy unless the
operator first grants one-time plaintext access with hasp session
grant-plaintext.

Examples
  hasp secret get OPENAI_API_KEY
  hasp secret retrieve OPENAI_API_KEY
`

const secretListHelpText = `hasp secret list

List vault items and metadata, including the safe named_reference form such as
@OPENAI_API_KEY.

Examples
  hasp secret list
  hasp secret list --json
`

const secretExposeHelpText = `hasp secret expose

Expose one vault item to one repo boundary and create the repo-scoped reference
that brokered commands use.

Use expose when a repo needs a secret by reference, not by raw value.

Examples
  hasp secret expose OPENAI_API_KEY --project-root .
`

const secretHideHelpText = `hasp secret hide

Remove one repo exposure for a secret. The vault item stays in the vault.

Examples
  hasp secret hide OPENAI_API_KEY --project-root .
`

const appHelpText = `hasp app

Connect a normal application to selected vault secrets.

An app consumer is machine-scoped by default. Add --project-root only when the
app should run inside a specific repo boundary.

Subcommands
  connect     save the app profile and optional launcher
  run         run the saved app command through HASP
  install     create or refresh the launcher
  shell       open a shell with the app bindings loaded
  disconnect  remove the app profile and managed launcher
  list        list saved app consumers

Learn more
  hasp help app connect
  hasp help app run
`

const appConnectHelpText = `hasp app connect

Save an app profile that maps vault secrets to env vars, temporary files, or a
temporary dotenv bundle.

Launcher creation is never silent. In interactive use, HASP asks. In scripts,
set --install=true or --install=false. If you install a launcher and its
directory is not on PATH, HASP can also patch your shell config, but only after
you say yes or pass --add-to-path=true.

Examples
  hasp app connect myapp --cmd 'python app.py' --env OPENAI_API_KEY=OPENAI_API_KEY
  hasp app connect myapp --cmd 'python app.py' --env OPENAI_API_KEY=OPENAI_API_KEY --install=true --add-to-path=true
  hasp app connect web --project-root . --cmd 'npm run dev' --dotenv DATABASE_URL=DATABASE_URL --dotenv-env ENV_FILE
`

const appRunHelpText = `hasp app run

Run the saved app command through HASP. Extra args after the app name are
forwarded to the saved command.

Examples
  hasp app run myapp
  hasp app run myapp --port 3000
`

const appInstallHelpText = `hasp app install

Create or refresh the managed launcher for an app consumer.

Use this when you skipped launcher creation during connect or when the launcher
path changed.

Examples
  hasp app install myapp
  hasp app install myapp --add-to-path=true
`

const appShellHelpText = `hasp app shell

Open a login shell with the app bindings loaded. Extra args are forwarded to
the shell command.

Examples
  hasp app shell myapp
`

const appDisconnectHelpText = `hasp app disconnect

Remove the saved app profile. If HASP manages the launcher path, it removes the
launcher too.

Examples
  hasp app disconnect myapp
`

const appListHelpText = `hasp app list

List saved app consumers.

Examples
  hasp app list
`

const agentHelpText = `hasp agent

Connect a coding agent to HASP once, then let it pull secrets through the MCP
surface or the local config HASP writes.

Agent consumers are usually repo-scoped. Pass --project-root when you want HASP
to bind the integration to one repo boundary.

Subcommands
  connect     write the agent config and save the consumer record
  mcp         run the agent-specific HASP MCP wrapper
  launch      run a command under an agent-safe HASP session
  shell       open a shell under an agent-safe HASP session
  disconnect  remove the agent config block and consumer record
  list        list saved agent consumers
  list-supported  list shipped/generic profile support proof

Learn more
  hasp help agent connect
  hasp help agent mcp
  hasp help agent launch
  hasp help agent shell
`

const agentConnectHelpText = `hasp agent connect

Write the local agent config needed for HASP integration and save that agent as
a managed consumer. Generated HASP MCP configs now point at a managed local
wrapper instead of a raw ` + "`hasp mcp`" + ` command so HASP can bind the
agent process tree to a protected session automatically.

Examples
  hasp agent connect claude-code --project-root .
  hasp agent connect codex-cli --project-root .
`

const agentMCPHelpText = `hasp agent mcp

Run the agent-specific HASP MCP wrapper. This opens an agent-safe session for
the saved consumer, registers the parent agent process with the daemon, and
then serves MCP on stdin/stdout.

Use this as the generated config path instead of raw ` + "`hasp mcp`" + ` for
first-class agent profiles.

Examples
  hasp agent mcp claude-code
  hasp agent mcp codex-cli
`

const agentLaunchHelpText = `hasp agent launch

Run a command under an agent-safe HASP session so subprocesses inherit
HASP_AGENT_SAFE_MODE and HASP_SESSION_TOKEN.

Use this when you want the whole agent process tree, not just the HASP MCP
server, to stay inside the protected policy context.

Examples
  hasp agent launch claude-code -- claude
  hasp agent launch codex-cli -- codex --model gpt-5.4
`

const agentShellHelpText = `hasp agent shell

Open a shell under an agent-safe HASP session so anything launched from that
shell inherits HASP_AGENT_SAFE_MODE and HASP_SESSION_TOKEN.

Examples
  hasp agent shell claude-code
  hasp agent shell codex-cli -c 'env | grep HASP_'
`

const agentDisconnectHelpText = `hasp agent disconnect

Remove the HASP config block for one agent consumer and delete the saved record.

Examples
  hasp agent disconnect claude-code
`

const agentListHelpText = `hasp agent list

List saved agent consumers.

Examples
  hasp agent list
`

const agentListSupportedHelpText = `hasp agent list-supported

List shipped and generic-compatible support profiles with docs, release-gate,
eval, benchmark, and connection proof.

Examples
  hasp agent list-supported
  hasp agent list-supported --json
`

const projectHelpText = `hasp project

Manage repo boundaries. Projects are where HASP applies guardrails, alias maps,
and leak detection.

Subcommands
  adopt     scan a directory tree and bind matching git repos
  bind      bind one repo and create its initial alias map
  status    inspect one bound repo
  unbind    remove one repo binding

Examples
  hasp project bind --project-root .
  hasp project status --project-root .
  hasp project adopt --under ~/Work
`

const runHelpText = `hasp run

Run one repo-scoped command through the broker with time-bound secret grants.

Use run when you want the repo boundary, approval model, and audit trail. Use
app run when you want a saved app consumer.

Examples
  hasp run --project-root . --env OPENAI_API_KEY=@OPENAI_API_KEY -- your-command
`

const injectHelpText = `hasp inject

Resolve repo-scoped refs into env vars or temporary files for one command.

Use inject for low-level brokered execution. App consumers are the simpler path
for repeatable non-repo apps.

Examples
  hasp inject --project-root . --file GOOGLE_APPLICATION_CREDENTIALS=@GOOGLE_APPLICATION_CREDENTIALS -- your-command
`

const writeEnvHelpText = `hasp write-env

Write a convenience env file from repo-scoped refs after explicit approval.

Use this when a tool truly needs a file on disk. Brokered run and inject are
safer because they avoid leaving values in the repo.

Examples
  hasp write-env --project-root . --output .env.local --env OPENAI_API_KEY=@OPENAI_API_KEY
`

const checkRepoHelpText = `hasp check-repo

Scan a repo for managed values that leaked into files.

Examples
  hasp check-repo --project-root .
`

const daemonHelpText = `hasp daemon

Manage the local runtime daemon.

Subcommands
  serve   run the daemon in the foreground
  start   start it in the background
  stop    stop it
  status  inspect it

Examples
  hasp daemon status
`

const sessionHelpText = `hasp session

Work with broker sessions directly.

Subcommands
  open      open a session for one repo boundary
  grant-plaintext  grant one-time plaintext reveal/copy for a protected session
  resolve   inspect an existing token
  revoke    revoke an existing token

Examples
  hasp session open --host-label local-cli --project-root .
  hasp session revoke --all
`

const sessionGrantPlaintextHelpText = `hasp session grant-plaintext

Grant one-time plaintext reveal/copy for an agent-safe session.

Use this as an explicit operator step before retrying ` + "`hasp secret get --reveal`" + `
or ` + "`--copy`" + ` inside a protected agent workflow. Approval is interactive
and local, and plaintext grants stay one-time, item-scoped, action-scoped, and
short-lived.

Examples
  hasp session grant-plaintext --token $HASP_SESSION_TOKEN --item OPENAI_API_KEY --action reveal --grant-window 60s
  hasp session grant-plaintext --token $HASP_SESSION_TOKEN --item OPENAI_API_KEY --action copy --grant-window 60s
`

const vaultHelpText = `hasp vault

Manage local vault/session material.

Subcommands
  lock  revoke active daemon sessions and grant material

Examples
  hasp vault lock
`

const vaultLockHelpText = `hasp vault lock

Revoke active daemon sessions and local grant material. This does not rotate
provider credentials.

Examples
  hasp vault lock
  hasp vault lock --json
`

const statusHelpText = `hasp status

Show local daemon and vault status.

Examples
  hasp status
  hasp status --json
`

const pingHelpText = `hasp ping

Check whether the local daemon can answer requests.

Examples
  hasp ping
`

const auditHelpText = `hasp audit

Print the local audit log.

Examples
  hasp audit
  hasp audit --incident-bundle --json
`

const exportBackupHelpText = `hasp export-backup

Write an encrypted backup for the local vault.

Examples
  hasp export-backup --output backup.json --recovery-passphrase 'passphrase'
`

const restoreBackupHelpText = `hasp restore-backup

Restore an encrypted backup into the current HASP home.

Examples
  hasp restore-backup --input backup.json --recovery-passphrase 'passphrase' --master-password 'new-password'
`

const mcpHelpText = `hasp mcp

Start the MCP server on stdin and stdout.

Use this from agent configs, not by hand, unless you are debugging the MCP
transport.

Examples
  hasp mcp
`

const tuiHelpText = `hasp tui

Open the terminal UI.

Examples
  hasp tui
`

const versionHelpText = `hasp version

Print the build version.

Examples
  hasp version
`
