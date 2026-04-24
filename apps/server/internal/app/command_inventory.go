package app

import (
	"context"
	"io"
	"slices"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/mcp"
)

const (
	commandGroupDaily   = "daily"
	commandGroupUtility = "utility"
)

type rootCommandHandler func(context.Context, []string, io.Reader, io.Writer, io.Writer, starter) error

type rootCommandSpec struct {
	name      string
	summary   string
	group     string
	helpTopic []string
	handler   rootCommandHandler
}

func rootCommandInventory() []rootCommandSpec {
	return []rootCommandSpec{
		{name: "init", summary: "create the local vault", group: commandGroupDaily, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return initCommandWithArgs(ctx, args, stdout)
		}},
		{name: "setup", summary: "guided machine, repo, and agent setup", group: commandGroupDaily, helpTopic: []string{"setup"}, handler: func(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return setupCommand(ctx, args, stdin, stdout, stderr)
		}},
		{name: "doctor", summary: "diagnose daemon, vault, binding, hooks, and audit state", group: commandGroupDaily, helpTopic: []string{"doctor"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return doctorCommand(ctx, args, stdout, s)
		}},
		{name: "list", summary: "shortcut for hasp secret list", group: commandGroupDaily, helpTopic: []string{"secret", "list"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return secretListCommand(ctx, args, stdout)
		}},
		{name: "get", summary: "shortcut for hasp secret get", group: commandGroupDaily, helpTopic: []string{"secret", "get"}, handler: func(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return secretGetCommand(ctx, args, stdin, stdout, stderr)
		}},
		{name: "secret", summary: "add, update, retrieve, expose, and hide vault items", group: commandGroupDaily, handler: func(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return secretCommand(ctx, args, stdin, stdout, stderr)
		}},
		{name: "app", summary: "connect an app profile and run it with managed secrets", group: commandGroupDaily, handler: appConsumerCommand},
		{name: "agent", summary: "connect an agent once and let it pull through HASP", group: commandGroupDaily, handler: func(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, _ starter) error {
			return agentConsumerCommand(ctx, args, stdin, stdout, stderr)
		}},
		{name: "vault", summary: "lock local vault/session material", group: commandGroupDaily, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return vaultCommand(ctx, args, stdout, s)
		}},
		{name: "project", summary: "bind, inspect, unbind, or bulk-adopt repo boundaries", group: commandGroupDaily, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return projectCommand(ctx, args, stdout)
		}},
		{name: "run", summary: "run a repo-scoped command through the broker", group: commandGroupDaily, helpTopic: []string{"run"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, s starter) error {
			return runCommand(ctx, args, stdout, stderr, s)
		}},
		{name: "inject", summary: "run a command with env or file refs resolved by HASP", group: commandGroupDaily, helpTopic: []string{"inject"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, s starter) error {
			return injectCommand(ctx, args, stdout, stderr, s)
		}},
		{name: "write-env", summary: "write a convenience env file on explicit request", group: commandGroupDaily, helpTopic: []string{"write-env"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, stderr io.Writer, s starter) error {
			return writeEnvCommand(ctx, args, stdout, stderr, s)
		}},
		{name: "check-repo", summary: "find managed values that leaked into a repo", group: commandGroupDaily, helpTopic: []string{"check-repo"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return checkRepoCommand(ctx, args, stdout)
		}},
		{name: "export-backup", summary: "write an encrypted backup", group: commandGroupDaily, helpTopic: []string{"export-backup"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return exportBackupCommand(ctx, args, stdout)
		}},
		{name: "restore-backup", summary: "restore an encrypted backup", group: commandGroupDaily, helpTopic: []string{"restore-backup"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return restoreBackupCommand(ctx, args, stdout)
		}},
		{name: "mcp", summary: "start the MCP server for agents", group: commandGroupDaily, helpTopic: []string{"mcp"}, handler: func(ctx context.Context, _ []string, stdin io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return mcp.Serve(ctx, stdin, stdout)
		}},
		{name: "import", summary: "import .env or JSON credentials", group: commandGroupUtility, helpTopic: []string{"import"}, handler: func(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return importCommandWithInput(ctx, args, stdin, stdout)
		}},
		{name: "set", summary: "add or replace one secret non-interactively", group: commandGroupUtility, helpTopic: []string{"set"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return setCommand(ctx, args, stdout)
		}},
		{name: "capture", summary: "save a value and optionally bind it to a repo", group: commandGroupUtility, helpTopic: []string{"capture"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return captureCommand(ctx, args, stdout, s)
		}},
		{name: "daemon", summary: "serve, start, stop, or inspect the local runtime", group: commandGroupUtility, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return daemonCommand(ctx, args, stdout, s)
		}},
		{name: "session", summary: "open, resolve, or revoke broker sessions", group: commandGroupUtility, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return sessionCommand(ctx, args, stdout, s)
		}},
		{name: "audit", summary: "print the local audit log", group: commandGroupUtility, helpTopic: []string{"audit"}, handler: func(_ context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return auditCommandWithArgs(args, stdout)
		}},
		{name: "status", summary: "show vault and daemon state", group: commandGroupUtility, helpTopic: []string{"status"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return statusCommandWithArgs(ctx, args, stdout, s)
		}},
		{name: "ping", summary: "check daemon reachability", group: commandGroupUtility, helpTopic: []string{"ping"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, s starter) error {
			return pingCommandWithArgs(ctx, args, stdout, s)
		}},
		{name: "tui", summary: "open the terminal UI", group: commandGroupUtility, helpTopic: []string{"tui"}, handler: func(ctx context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return tuiCommand(ctx, args, stdout)
		}},
		{name: "version", summary: "print the build version", group: commandGroupUtility, handler: func(_ context.Context, args []string, _ io.Reader, stdout io.Writer, _ io.Writer, _ starter) error {
			return versionCommand(args, stdout)
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
	return spec.handler(ctx, args, stdin, stdout, stderr, s)
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
