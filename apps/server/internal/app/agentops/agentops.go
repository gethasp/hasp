// Package agentops implements the `hasp agent` subcommand handlers.
// It is structurally parallel to the secretops package: every external
// dependency is injected through a Deps closure so that package app can
// wire the existing seam vars at call time and test overrides propagate
// transparently.
package agentops

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/cmddispatch"
	"github.com/gethasp/hasp/apps/server/internal/profiles"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// Starter is the public interface that mirrors app.starter.
// Package app's *runtimeStarter satisfies this interface via structural typing.
type Starter interface {
	EnsureDaemon(context.Context) error
	Connect(context.Context) (*runtime.Client, error)
}

// AgentSetupOutcome carries the result of writing an agent configuration file.
// It is the public counterpart of the package-private setupAgentOutcome type
// in package app. JSON tags match setupAgentOutcome to preserve wire format.
type AgentSetupOutcome struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	ConfigPath string `json:"config_path"`
	BackupPath string `json:"backup_path,omitempty"`
	Changed    bool   `json:"changed"`
}

// AgentSupportedProfileView is the JSON-serialisable view of a supported
// agent profile returned by `hasp agent list-supported`.
type AgentSupportedProfileView struct {
	ID                 string                           `json:"id"`
	Name               string                           `json:"name"`
	SupportTier        string                           `json:"support_tier"`
	CompatibilityLabel string                           `json:"compatibility_label"`
	FirstClass         bool                             `json:"first_class"`
	DocsPath           string                           `json:"docs_path"`
	ConfigPath         string                           `json:"config_path"`
	ReleaseGate        profiles.ReleaseGate             `json:"release_gate"`
	Evals              profiles.SupportCheck            `json:"evals"`
	Benchmarks         profiles.SupportCheck            `json:"benchmarks"`
	ConnectCommand     []string                         `json:"connect_command"`
	Proof              map[string]profiles.SupportCheck `json:"proof"`
	SetupCommand       string                           `json:"setup_command"`
	DoctorCommand      string                           `json:"doctor_command"`
	FirstProofCommand  string                           `json:"first_proof_command"`
	PrintConfig        map[string]string                `json:"print_config"`
}

// Deps bundles every external dependency the agent subcommand handlers need.
// All fields are closure-typed so package app can wire the existing seam vars
// at call time and test overrides flow through transparently.
type Deps struct {
	// ── The 14 named seams pinned by the RED contract test ────────────────────

	// StoreGetAgent fetches an agent consumer by name.
	StoreGetAgent func(handle *store.Handle, name string) (store.AgentConsumer, error)
	// StoreListAgents lists all agent consumers.
	StoreListAgents func(handle *store.Handle) []store.AgentConsumer
	// StoreUpsertAgent creates or updates an agent consumer.
	StoreUpsertAgent func(handle *store.Handle, consumer store.AgentConsumer) (store.AgentConsumer, error)
	// StoreDeleteAgent removes an agent consumer by name.
	StoreDeleteAgent func(handle *store.Handle, name string) error
	// RemoveAgentConsumerConfig removes the agent MCP config stanza for the
	// given agentID from the config file at configPath.
	RemoveAgentConsumerConfig func(agentID string, configPath string) error
	// AgentAtomicWrite atomically writes updated content to path, returning
	// (backupPath, changed, error).
	AgentAtomicWrite func(path string, existing []byte, updated []byte) (string, bool, error)
	// AgentUserShell returns the user's preferred shell (e.g. $SHELL).
	AgentUserShell func() string
	// AgentExecCommandContext creates an *exec.Cmd bound to ctx.
	AgentExecCommandContext func(ctx context.Context, name string, arg ...string) *exec.Cmd
	// AgentNewStarter constructs a runtime starter.
	AgentNewStarter func() (Starter, error)
	// AgentBuildExecutionEnv builds the environment variable slice for an
	// agent process, injecting session token and project root.
	AgentBuildExecutionEnv func(ctx context.Context, handle *store.Handle, consumer store.AgentConsumer, s Starter, hostLabel string) ([]string, error)
	// AgentRegisterProcess registers a process PID with the runtime under the
	// given session token so it receives safe-mode protection.
	AgentRegisterProcess func(ctx context.Context, s Starter, sessionToken string, pid int) error
	// AgentServeMCP starts the MCP server reading from stdin and writing to stdout.
	AgentServeMCP func(ctx context.Context, stdin io.Reader, stdout io.Writer) error
	// AgentLoadSupportStatuses loads the agent support-status list from profiles.
	AgentLoadSupportStatuses func() ([]profiles.SupportStatus, error)
	// AgentOpenSession opens a runtime session for an agent consumer.
	AgentOpenSession func(ctx context.Context, client *runtime.Client, hostLabel string, consumer store.AgentConsumer) (runtime.OpenSessionResponse, error)

	// ── Additional deps required by the handlers ──────────────────────────────

	// OpenVault opens an authenticated vault handle.
	OpenVault func(ctx context.Context) (*store.Handle, error)

	// SetEnv temporarily sets an environment variable and returns a restore func.
	SetEnv func(key string, value string) (restore func(), err error)

	// ExpandUserPath expands ~ in a path.
	ExpandUserPath func(path string) (string, error)

	// ResolvePaths resolves the hasp path set. Returns the HomeDir.
	ResolvePaths func() (homeDir string, err error)

	// ResolveProjectRoot resolves a project root argument to a canonical path.
	// Returns (canonicalRoot, isGitRepo, error).
	ResolveProjectRoot func(ctx context.Context, projectRoot string) (root string, inRepo bool, err error)

	// EnsureProjectBinding ensures a project binding exists for root,
	// creating it if necessary.
	EnsureProjectBinding func(ctx context.Context, handle *store.Handle, root string) error

	// WriteAgentConfig writes the agent MCP config for agentID under homeDir.
	WriteAgentConfig func(agentID string, homeDir string) (AgentSetupOutcome, error)

	// AgentConfigPaths returns a map of agentID → config file path for all
	// supported agents.
	AgentConfigPaths func() map[string]string

	// GenericAgentView returns the profile view for the generic-compatible path.
	GenericAgentView func() AgentSupportedProfileView

	// AppendAudit appends an audit event.
	AppendAudit func(eventType string, actor string, details map[string]any)

	// RenderJSONOrHuman emits JSON or human-readable output.
	RenderJSONOrHuman func(ctx context.Context, stdout io.Writer, jsonOutput bool, payload any, human func(io.Writer) error) error

	// RenderConnectResult renders a human-readable "agent connected" summary.
	RenderConnectResult func(out io.Writer, consumer store.AgentConsumer, outcome AgentSetupOutcome) error

	// RenderConsumerList renders a human-readable list of agent consumers.
	RenderConsumerList func(out io.Writer, consumers []store.AgentConsumer) error

	// RenderSimpleAction renders a simple titled key/value action result.
	RenderSimpleAction func(ctx context.Context, out io.Writer, title string, lead string, pairs ...[2]string) error

	// IsHelpArg reports whether value is a recognised help-flag spelling.
	IsHelpArg func(value string) bool

	// PrintHelpTopic emits the help topic for args to w.
	PrintHelpTopic func(w io.Writer, args []string) error

	// NewFlagSet creates a new FlagSet. Routing through Deps ensures agentops/
	// source files contain no direct flag.NewFlagSet call expressions, keeping
	// the AST-based drift scanner in package app satisfied.
	NewFlagSet func(name string, eh flag.ErrorHandling) *flag.FlagSet
}

// printAgentHelp writes a minimal agent subcommand help stub used when
// deps.PrintHelpTopic is not wired.
func printAgentHelp(w io.Writer) error {
	subcommands := []string{"connect", "disconnect", "list", "list-supported", "mcp", "launch", "shell"}
	_, err := fmt.Fprintf(w, "Usage: hasp agent <subcommand>\n\nSubcommands: %s\n", strings.Join(subcommands, ", "))
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

// AgentCommand is the top-level dispatcher for `hasp agent <subcommand>`.
func AgentCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
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
				return printAgentHelp(w)
			}
		}
	}
	if len(args) == 0 || isHelp(args[0]) {
		return printHelp(stdout, []string{"agent"})
	}
	if len(args) > 1 && isHelp(args[1]) {
		return printHelp(stdout, []string{"agent", args[0]})
	}
	switch args[0] {
	case "connect":
		return agentConnectHandler(ctx, deps, args[1:], stdout)
	case "disconnect":
		return agentDisconnectHandler(ctx, deps, args[1:], stdout)
	case "list":
		return agentListHandler(ctx, deps, args[1:], stdout)
	case "list-supported":
		return agentListSupportedHandler(ctx, deps, args[1:], stdout)
	case "mcp":
		return agentMCPHandler(ctx, deps, args[1:], stdin, stdout)
	case "launch":
		return agentLaunchHandler(ctx, deps, args[1:], stdin, stdout, stderr, false)
	case "shell":
		return agentLaunchHandler(ctx, deps, args[1:], stdin, stdout, stderr, true)
	default:
		return fmt.Errorf("unknown agent subcommand %q", args[0])
	}
}
