package app

import (
	"context"
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/gethasp/hasp/apps/server/internal/mcp"
)

const (
	commandGroupDaily   = "daily"
	commandGroupUtility = "utility"
)

type rootCommandHandler func(context.Context, []string, io.Reader, io.Writer, io.Writer, starter) error

type rootCommandSpec struct {
	name        string
	summary     string
	group       string
	helpTopic   []string
	subcommands []string
	hidden      bool
	handler     rootCommandHandler
}

var (
	rootCommandsOnce   sync.Once
	rootCommandsCached []rootCommandSpec
)

func rootCommandInventory() []rootCommandSpec {
	rootCommandsOnce.Do(func() {
		rootCommandsCached = buildRootCommandInventory()
	})
	return rootCommandsCached
}

func buildRootCommandInventory() []rootCommandSpec {
	return []rootCommandSpec{
		{name: "init", summary: "create the local vault", group: commandGroupUtility, helpTopic: []string{"init"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			noteSetupCanonical(stderr, "hasp init")
			return initCommandWithArgs(ctx, args, stdout)
		}},
		{name: "setup", summary: "guided machine, repo, and agent setup", group: commandGroupDaily, helpTopic: []string{"setup"}, handler: func(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return setupCommand(ctx, args, stdin, stdout, stderr)
		}},
		{name: "bootstrap", summary: "configure a repo and an agent profile in one operator-focused flow", group: commandGroupUtility, helpTopic: []string{"bootstrap"}, handler: func(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return bootstrapCommandWithInput(ctx, args, stdin, stdout, bootstrapVerification)
		}},
		{name: "doctor", summary: "diagnose daemon, vault, binding, hooks, and audit state", group: commandGroupDaily, helpTopic: []string{"doctor"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return doctorCommand(ctx, args, stdout, s)
		}},
		{name: "secret", summary: "add, update, show/reveal/copy, expose, and hide vault items", group: commandGroupDaily, subcommands: []string{"add", "copy", "delete", "diff", "expose", "get", "hide", "list", "reveal", "rotate", "search", "show", "update"}, handler: func(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return secretCommand(ctx, args, stdin, stdout, stderr)
		}},
		{name: "app", summary: "connect an app profile and run it with managed secrets", group: commandGroupDaily, subcommands: []string{"connect", "disconnect", "install", "list", "run", "shell"}, handler: appConsumerCommand},
		{name: "agent", summary: "connect an agent once and let it pull through HASP", group: commandGroupDaily, subcommands: []string{"connect", "disconnect", "launch", "list", "list-supported", "mcp", "shell"}, handler: func(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return agentConsumerCommand(ctx, args, stdin, stdout, stderr)
		}},
		{name: "vault", summary: "lock local vault/session material", group: commandGroupUtility, subcommands: []string{"lock", "forget-device"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return vaultCommand(ctx, args, stdout, s)
		}},
		{name: "project", summary: "bind, inspect, unbind, or bulk-adopt repo boundaries", group: commandGroupUtility, subcommands: []string{"adopt", "bind", "doctor", "examples", "requirements", "status", "targets", "unbind"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return projectCommandWithStderr(ctx, args, stdout, stderr)
		}},
		{name: "run", summary: "run a repo-scoped command through the broker", group: commandGroupDaily, helpTopic: []string{"run"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, s starter) error {
			return runCommand(ctx, args, stdout, stderr, s)
		}},
		{name: "inject", summary: "run a command with env or file refs resolved by HASP", group: commandGroupDaily, helpTopic: []string{"inject"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, s starter) error {
			return injectCommand(ctx, args, stdout, stderr, s)
		}},
		{name: "write-env", summary: "write a convenience env file on explicit request", group: commandGroupUtility, helpTopic: []string{"write-env"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, s starter) error {
			return writeEnvCommand(ctx, args, stdout, stderr, s)
		}},
		{name: "check-repo", summary: "find managed values that leaked into a repo", group: commandGroupUtility, helpTopic: []string{"check-repo"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return checkRepoCommand(ctx, args, stdout, stderr)
		}},
		{name: "proof", summary: "run the brokered first-proof check (replaces the long quickstart one-liner)", group: commandGroupDaily, helpTopic: []string{"proof"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, s starter) error {
			return proofCommand(ctx, args, stdout, stderr, s)
		}},
		{name: "export-backup", summary: "write an encrypted backup", group: commandGroupUtility, helpTopic: []string{"export-backup"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return exportBackupCommand(ctx, args, stdout)
		}},
		{name: "restore-backup", summary: "restore an encrypted backup", group: commandGroupUtility, helpTopic: []string{"restore-backup"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return restoreBackupCommand(ctx, args, stdout)
		}},
		{name: "mcp", summary: "start the MCP server for agents", group: commandGroupUtility, helpTopic: []string{"mcp"}, handler: func(ctx context.Context, _ []string, stdin io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return mcp.Serve(ctx, stdin, stdout)
		}},
		{name: "import", summary: "import .env or JSON credentials", group: commandGroupUtility, helpTopic: []string{"import"}, handler: func(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return importCommandWithInput(ctx, args, stdin, stdout)
		}},
		{name: "set", summary: "add or replace one secret non-interactively", group: commandGroupUtility, helpTopic: []string{"set"}, handler: func(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return setCommand(ctx, args, stdin, stdout, stderr)
		}},
		{name: "capture", summary: "save a value and optionally bind it to a repo", group: commandGroupUtility, helpTopic: []string{"capture"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, s starter) error {
			emitDeprecationWarning(ctx, stderr, "[hasp] 'hasp capture' is deprecated; use 'hasp secret add' with --expose=always (or --vault-only).\n")
			return captureCommand(ctx, args, stdout, s)
		}},
		{name: "daemon", summary: "serve, start, stop, or inspect the local runtime", group: commandGroupUtility, subcommands: []string{"http-key", "restart", "run", "serve", "start", "status", "stop"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return daemonCommand(ctx, args, stdout, s)
		}},
		{name: "session", summary: "open, resolve, or revoke broker sessions", group: commandGroupUtility, subcommands: []string{"grant-plaintext", "list", "open", "resolve", "revoke"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return sessionCommand(ctx, args, stdout, s)
		}},
		{name: "lease", summary: "list or revoke active broker leases", group: commandGroupUtility, helpTopic: []string{"lease"}, subcommands: []string{"list", "revoke"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return leaseCommand(ctx, args, stdout, s)
		}},
		{name: "approval", summary: "list or decide broker approval requests", group: commandGroupUtility, helpTopic: []string{"approval"}, subcommands: []string{"decide", "list"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return approvalCommand(ctx, args, stdout, s)
		}},
		{name: "access", summary: "inspect consumer-to-secret access grants", group: commandGroupUtility, helpTopic: []string{"access"}, subcommands: []string{"matrix"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return accessCommand(ctx, args, stdout, s)
		}},
		{name: "policy", summary: "show, validate, or replace access policy rules", group: commandGroupUtility, helpTopic: []string{"policy"}, subcommands: []string{"set", "show", "validate"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return policyCommand(ctx, args, stdout, s)
		}},
		{name: "config", summary: "show, get, or set daemon settings", group: commandGroupUtility, helpTopic: []string{"config"}, subcommands: []string{"get", "set", "show"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return configCommand(ctx, args, stdout, s)
		}},
		{name: "audit", summary: "print the local audit log", group: commandGroupUtility, helpTopic: []string{"audit"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return auditCommandWithArgs(ctx, args, stdout)
		}},
		{name: "status", summary: "show vault and daemon state", group: commandGroupUtility, helpTopic: []string{"status"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return statusCommandWithArgs(ctx, args, stdout, s)
		}},
		{name: "ping", summary: "check daemon reachability", group: commandGroupUtility, helpTopic: []string{"ping"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return pingCommandWithArgs(ctx, args, stdout, s)
		}},
		{name: "tui", summary: "deprecated: print a one-shot project snapshot (use `hasp project status`)", group: commandGroupUtility, helpTopic: []string{"tui"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return tuiCommand(ctx, args, stdout, stderr)
		}},
		{name: "version", summary: "print the build version", group: commandGroupUtility, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return versionCommand(ctx, args, stdout)
		}},
		{name: "completion", summary: "emit a shell completion script", group: commandGroupUtility, helpTopic: []string{"completion"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return completionCommand(ctx, args, stdout, stderr)
		}},
		{name: "upgrade", summary: "download and install a signed newer hasp release", group: commandGroupUtility, helpTopic: []string{"upgrade"}, handler: func(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return upgradeCommand(ctx, args, stdin, stdout, stderr)
		}},
		{name: "docs", summary: "render every help topic as a markdown reference", group: commandGroupUtility, helpTopic: []string{"docs"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return docsCommand(ctx, args, stdout, stderr)
		}},
		{name: "redact", summary: "stream-filter stdin and rewrite known managed values", group: commandGroupUtility, hidden: true, handler: func(ctx context.Context, _ []string, stdin io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return redactCommand(ctx, stdin, stdout)
		}},
		// hasp-czal: hidden completion entry point. Shell scripts shell out to
		// `hasp __complete <words...>` so nested completion stays in lock-step
		// with the live dispatcher rather than re-encoded per shell.
		{name: "__complete", summary: "internal: emit completions for the given partial argv", group: commandGroupUtility, hidden: true, handler: func(_ context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			for _, candidate := range Complete(args, CompletionOptions{}) {
				if _, err := io.WriteString(stdout, candidate+"\n"); err != nil {
					return err
				}
			}
			return nil
		}},
	}
}

func lookupRootCommand(name string) (rootCommandSpec, bool) {
	commands := rootCommandInventory()
	index := slices.IndexFunc(commands, func(spec rootCommandSpec) bool {
		return spec.name == strings.TrimSpace(name)
	})
	if index < 0 {
		return rootCommandSpec{}, false
	}
	return commands[index], true
}

func dispatchRootCommand(ctx context.Context, spec rootCommandSpec, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, s starter) error {
	if len(spec.helpTopic) > 0 && len(args) > 0 && isHelpArg(args[0]) {
		return printHelpTopic(stdout, spec.helpTopic)
	}
	// hasp-khcj: rewrite flag-package error messages to the double-dash form
	// users actually type before they bubble up to the CLI driver.
	return rewriteFlagDashForm(spec.handler(ctx, args, stdin, stdout, stderr, s))
}

func rootCommandsByGroup(group string) []rootCommandSpec {
	filtered := make([]rootCommandSpec, 0)
	for _, spec := range rootCommandInventory() {
		if spec.group == group {
			filtered = append(filtered, spec)
		}
	}
	return filtered
}
