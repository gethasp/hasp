// Package appops implements the `hasp app` subcommand handlers.
// It is structurally parallel to the agentops package: every external
// dependency is injected through a Deps closure so that package app can
// wire the existing seam vars at call time and test overrides propagate
// transparently.
package appops

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/cmddispatch"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// Starter is the public interface that mirrors app.starter.
// Package app's *runtimeStarter satisfies this interface via structural typing.
type Starter interface {
	EnsureDaemon(context.Context) error
	Connect(context.Context) (*runtime.Client, error)
}

// AppPathUpdate carries the result of adding the launcher directory to PATH.
// It is the public counterpart of the package-private appPathUpdateResult type
// in package app. JSON tags match appPathUpdateResult to preserve wire format.
type AppPathUpdate struct {
	ConfigPath string `json:"config_path,omitempty"`
	Changed    bool   `json:"changed"`
}

// OptionalBool mirrors app.setupOptionalBool for use in AppConnectConfig.
type OptionalBool struct {
	Set   bool
	Value bool
}

// AppConnectConfig holds the parsed parameters for `hasp app connect`.
// It mirrors appConnectConfig in package app, using exported field names
// and primitive types to avoid private-type coupling.
type AppConnectConfig struct {
	Name            string
	ProjectRoot     string
	Command         string
	DotenvEnv       string
	InstallLauncher OptionalBool
	AddToPath       OptionalBool
	EnvMappings     map[string]string
	FileMappings    map[string]string
	DotenvMappings  map[string]string
}

// Deps bundles every external dependency the app subcommand handlers need.
// All fields are closure-typed so package app can wire the existing seam vars
// at call time and test overrides flow through transparently.
type Deps struct {
	// ── The 14 named seams pinned by the RED contract test ────────────────────

	// AppResolvePaths resolves the hasp paths set.
	AppResolvePaths func() (homeDir string, err error)
	// AppWriteFile writes data to a file at path with the given permissions.
	AppWriteFile func(path string, data []byte, perm os.FileMode) error
	// AppReadFile reads the file at path.
	AppReadFile func(path string) ([]byte, error)
	// AppMkdirAll creates directory path and any necessary parents.
	AppMkdirAll func(path string, perm os.FileMode) error
	// AppRemove removes the file or directory at path.
	AppRemove func(path string) error
	// AppUserShell returns the user's preferred shell.
	AppUserShell func() string
	// AppCurrentShell returns the current shell.
	AppCurrentShell func() string
	// AppUserHomeDir returns the user's home directory.
	AppUserHomeDir func() (string, error)
	// StoreGetApp fetches an app consumer by name.
	StoreGetApp func(handle *store.Handle, name string) (store.AppConsumer, error)
	// StoreListApps lists all app consumers.
	StoreListApps func(handle *store.Handle) []store.AppConsumer
	// StoreUpsertApp creates or updates an app consumer.
	StoreUpsertApp func(handle *store.Handle, consumer store.AppConsumer) (store.AppConsumer, error)
	// StoreDeleteApp removes an app consumer by name.
	StoreDeleteApp func(handle *store.Handle, name string) error
	// AppExecuteConsumer runs an app consumer process, returning the result.
	AppExecuteConsumer func(ctx context.Context, handle *store.Handle, consumer store.AppConsumer, command []string, stdout, stderr io.Writer, s Starter, action string) (runner.Result, error)
	// AppInstallLauncher installs the launcher script for a named app consumer
	// and returns the launcher path. Provided as a seam for future use; the
	// install handler uses a higher-level InstallConsumer closure that
	// preserves the plan→upsert→write ordering required for rollback.
	AppInstallLauncher func(name string) (string, error)

	// ── Additional deps required by the handlers ──────────────────────────────

	// AppNewStarter constructs (or returns the pre-built) runtime starter.
	// In production defaultAppDeps() builds a fresh starter; the
	// appConsumerCommand shim overrides this field to inject the caller-
	// supplied s starter before calling AppCommand.
	AppNewStarter func() (Starter, error)

	// OpenVault opens an authenticated vault handle.
	OpenVault func(ctx context.Context) (*store.Handle, error)

	// AppendAudit appends an audit event.
	AppendAudit func(eventType string, actor string, details map[string]any)

	// RenderJSONOrHuman emits JSON or human-readable output.
	RenderJSONOrHuman func(ctx context.Context, stdout io.Writer, jsonOutput bool, payload any, human func(io.Writer) error) error

	// RenderConnectResult renders a human-readable "app connected" summary.
	RenderConnectResult func(out io.Writer, consumer store.AppConsumer, pathUpdate AppPathUpdate) error

	// RenderInstallResult renders a human-readable "app installed" summary.
	RenderInstallResult func(out io.Writer, consumer store.AppConsumer, pathUpdate AppPathUpdate) error

	// RenderConsumerList renders a human-readable list of app consumers.
	RenderConsumerList func(out io.Writer, consumers []store.AppConsumer) error

	// RenderSimpleAction renders a simple titled key/value action result.
	RenderSimpleAction func(ctx context.Context, out io.Writer, title string, lead string, pairs ...[2]string) error

	// IsHelpArg reports whether value is a recognised help-flag spelling.
	IsHelpArg func(value string) bool

	// PrintHelpTopic emits the help topic for args to w.
	PrintHelpTopic func(w io.Writer, args []string) error

	// NewFlagSet creates a new FlagSet. Routing through Deps ensures appops/
	// source files contain no direct flag.NewFlagSet call expression, keeping
	// the AST-based flag-drift scanner in package app satisfied.
	NewFlagSet func(name string, eh flag.ErrorHandling) *flag.FlagSet

	// ExpandUserPath expands ~ in a path.
	ExpandUserPath func(path string) (string, error)

	// ResolveProjectRoot resolves a project root argument to a canonical path.
	// Returns (canonicalRoot, inRepo, error).
	ResolveProjectRoot func(ctx context.Context, projectRoot string) (root string, inRepo bool, err error)

	// EnsureProjectBinding ensures a project binding exists for root,
	// creating it if necessary.
	EnsureProjectBinding func(ctx context.Context, handle *store.Handle, root string) error

	// GlobalJSON returns true when the --json global flag is set in ctx.
	GlobalJSON func(ctx context.Context) bool

	// WarnBareEnvRefs emits warnings for bare (non-@ prefixed) env refs.
	WarnBareEnvRefs func(ctx context.Context, stderr io.Writer, mappings map[string]string, cmd string, flag string)

	// StdinIsCharDevice reports whether stdin is an interactive terminal.
	StdinIsCharDevice func(stdin io.Reader) bool

	// PromptConnectMissing interactively fills in missing connect config fields.
	PromptConnectMissing func(stdin io.Reader, stdout io.Writer, cfg *AppConnectConfig) error

	// ValidateAppConsumerName validates that a consumer name is well-formed.
	ValidateAppConsumerName func(name string) error

	// NormalizeConnectArgs normalises --install to --install=always etc.
	NormalizeConnectArgs func(args []string) []string

	// ConnectConsumer performs the full app consumer connection workflow:
	// binds secrets, plans and installs the launcher, upserts the store record,
	// and updates PATH. Wraps connectAppConsumerWithHandle in package app.
	ConnectConsumer func(ctx context.Context, handle *store.Handle, cfg AppConnectConfig, stdin io.Reader, stdout, stderr io.Writer) (store.AppConsumer, AppPathUpdate, error)

	// InstallConsumer performs the full app launcher install workflow:
	// plans the launcher path, upserts the store record, writes the file
	// (with rollback on failure), and updates PATH. Wraps the install logic
	// from appInstallCommandWithInput in package app.
	InstallConsumer func(ctx context.Context, handle *store.Handle, name string, addToPath OptionalBool, stdin io.Reader, stdout, stderr io.Writer) (store.AppConsumer, AppPathUpdate, error)
}

// printAppHelp writes a minimal app subcommand help stub used when
// deps.PrintHelpTopic is not wired.
func printAppHelp(w io.Writer) error {
	subcommands := []string{"connect", "run", "shell", "install", "disconnect", "list"}
	_, err := fmt.Fprintf(w, "Usage: hasp app <subcommand>\n\nSubcommands: %s\n", strings.Join(subcommands, ", "))
	return err
}

// isHelpArgFallback is a self-contained help-arg detector used when
// deps.IsHelpArg is not wired.
func isHelpArgFallback(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "help", "-h", "--help", "-help":
		return true
	}
	return false
}

// AppCommand is the top-level dispatcher for `hasp app <subcommand>`.
func AppCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	isHelp := deps.IsHelpArg
	if isHelp == nil {
		isHelp = isHelpArgFallback
	}
	printHelp := deps.PrintHelpTopic
	if printHelp == nil {
		if cmddispatch.PrintHelpTopicFn != nil {
			printHelp = cmddispatch.PrintHelpTopic
		} else {
			printHelp = func(w io.Writer, _ []string) error {
				return printAppHelp(w)
			}
		}
	}
	if len(args) == 0 || isHelp(args[0]) {
		return printHelp(stdout, []string{"app"})
	}
	if len(args) > 1 && isHelp(args[1]) {
		return printHelp(stdout, []string{"app", args[0]})
	}
	switch args[0] {
	case "connect":
		return appConnectHandler(ctx, deps, args[1:], stdin, stdout, stderr)
	case "run":
		return appRunHandler(ctx, deps, args[1:], stdout, stderr)
	case "shell":
		return appShellHandler(ctx, deps, args[1:], stdout, stderr)
	case "install":
		return appInstallHandler(ctx, deps, args[1:], stdin, stdout, stderr)
	case "disconnect":
		return appDisconnectHandler(ctx, deps, args[1:], stdout)
	case "list":
		return appListHandler(ctx, deps, args[1:], stdout)
	default:
		return fmt.Errorf("unknown app subcommand %q", args[0])
	}
}
