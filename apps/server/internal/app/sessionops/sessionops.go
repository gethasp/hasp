// Package sessionops implements the `hasp session` subcommand handlers.
// It is structurally parallel to the other ops packages: every external
// dependency is injected through a Deps closure so that package app can
// wire the existing seam vars at call time and test overrides propagate
// transparently.
package sessionops

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/vaultops"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// Starter is the public interface that mirrors app.starter.
// Package app's *runtimeStarter satisfies this interface via structural typing.
type Starter interface {
	EnsureDaemon(context.Context) error
	Connect(context.Context) (*runtime.Client, error)
}

// LocalDeps bundles the seams that personalise session-related CLI commands:
// the plaintext-grant approval prompt (Approve), the store-side grant
// issuance (UseGrant), and the local-user lookup that "session list --mine"
// filters on. Tests construct a local instance to inject deterministic
// outcomes without touching package-level vars.
type LocalDeps struct {
	Approve   func(session runtime.SessionView, itemName string, action store.PlaintextAction) error
	UseGrant  func(handle *store.Handle, token string, itemName string, action store.PlaintextAction, window time.Duration) (store.PlaintextGrant, error)
	LocalUser func() (string, error)
}

// ConfirmPlaintextGrantDeps wires the platform inputs that the operator
// approval prompt depends on (current GOOS for choosing macOS osascript vs
// terminal flow, exec.Command factory for shelling osascript, UnderTest
// to short-circuit the whole prompt under "go test"). Tests build a local
// instance to drive each branch deterministically.
type ConfirmPlaintextGrantDeps struct {
	GOOS      string
	Command   func(name string, arg ...string) *exec.Cmd
	UnderTest func() bool
}

// Deps bundles every external dependency the session subcommand handlers need.
// All fields are closure-typed so package app can wire the existing seam vars
// at call time and test overrides flow through transparently.
type Deps struct {
	// OpenVault opens an authenticated vault handle.
	OpenVault func(ctx context.Context) (*store.Handle, error)

	// CanonicalProjectRoot resolves a raw project root argument to its
	// canonical path (store.CanonicalProjectRoot).
	CanonicalProjectRoot func(ctx context.Context, root string) (string, error)

	// EnsureProjectBinding ensures a project binding exists for root.
	EnsureProjectBinding func(ctx context.Context, handle *store.Handle, root string) error

	// GetItem fetches a vault item by name.
	GetItem func(handle *store.Handle, name string) (store.Item, error)

	// NewStarter constructs a runtime Starter.
	NewStarter func() (Starter, error)

	// RenderJSONOrHuman emits JSON or human-readable output.
	RenderJSONOrHuman func(ctx context.Context, stdout io.Writer, jsonOutput bool, payload any, human func(io.Writer) error) error

	// RenderSimpleAction renders a simple titled key/value action result.
	RenderSimpleAction func(ctx context.Context, out io.Writer, title string, lead string, pairs ...[2]string) error

	// IsHelpArg reports whether value is a recognised help-flag spelling.
	IsHelpArg func(value string) bool

	// PrintHelpTopic emits the help topic for args to w.
	PrintHelpTopic func(w io.Writer, args []string) error

	// GlobalJSON reports whether the global --json flag is set.
	GlobalJSON func(ctx context.Context) bool

	// ParsePlaintextAction parses a plaintext action string.
	ParsePlaintextAction func(value string) (store.PlaintextAction, error)

	// ParseGrantScope parses a grant scope string.
	ParseGrantScope func(value string) store.GrantScope

	// RenderSessionOpenResult renders the human-readable session open result.
	RenderSessionOpenResult func(out io.Writer, sessionID string, hostLabel string, projectRoot string, expiresAt string) error

	// RenderSessionResolveResult renders the human-readable session resolve result.
	RenderSessionResolveResult func(out io.Writer, reply runtime.ResolveSessionResponse) error

	// GrantOps bundles the store-level operations needed by session revoke --all.
	// When nil, the handler is unable to revoke vault-side grants.
	GrantOps func() vaultops.GrantOpsDeps

	// ExpandUserPath expands ~ in a path.
	ExpandUserPath func(path string) (string, error)

	// SecretIsCharDevice reports whether a file is a char device (tty).
	SecretIsCharDevice func(f interface{ Fd() uintptr }) bool

	// StdinFile returns the *os.File for an io.Reader if it is stdin.
	StdinFile func(r io.Reader) (interface{ Fd() uintptr }, bool)

	// DefaultLocalDeps returns the default LocalDeps (wired to seam vars).
	DefaultLocalDeps func() LocalDeps

	// DefaultConfirmPlaintextGrantDeps returns the default ConfirmPlaintextGrantDeps.
	DefaultConfirmPlaintextGrantDeps func() ConfirmPlaintextGrantDeps

	// GlobalColorOptions returns the color opts for the current context.
	GlobalColorOptions func(ctx context.Context, stdout io.Writer) ColorOptions
}

// ColorOptions mirrors ui.ColorOptions and is used by the GlobalColorOptions
// closure so callers in package app can pass color settings without a direct
// ui package dependency in tests.
type ColorOptions struct {
	Interactive bool
	Disable     bool
	Quiet       bool
	Verbose     bool
}

// printSessionHelp writes a minimal session subcommand help stub used when
// deps.PrintHelpTopic is not wired.
func printSessionHelp(w io.Writer) error {
	subcommands := []string{"open", "grant-plaintext", "revoke", "list", "resolve"}
	_, err := fmt.Fprintf(w, "Usage: hasp session <subcommand>\n\nSubcommands: %s\n", strings.Join(subcommands, ", "))
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

// SessionCommand is the top-level dispatcher for `hasp session <subcommand>`.
func SessionCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	isHelp := deps.IsHelpArg
	if isHelp == nil {
		isHelp = isHelpArgFallback
	}
	printHelp := deps.PrintHelpTopic
	if printHelp == nil {
		printHelp = func(w io.Writer, _ []string) error {
			return printSessionHelp(w)
		}
	}
	if len(args) == 0 || isHelp(args[0]) {
		return printHelp(stdout, []string{"session"})
	}
	switch args[0] {
	case "open":
		return sessionOpen(ctx, deps, args[1:], stdout)
	case "grant-plaintext":
		return sessionGrantPlaintext(ctx, deps, args[1:], stdout, nil)
	case "resolve":
		return sessionResolve(ctx, deps, args[1:], stdout)
	case "revoke":
		return sessionRevoke(ctx, deps, args[1:], stdout)
	case "list":
		return sessionList(ctx, deps, args[1:], stdout)
	default:
		return fmt.Errorf("unknown session subcommand %q", args[0])
	}
}
