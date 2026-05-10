// Package runtimeops implements the top-level runtime subcommand handlers
// (export-backup, restore-backup, tui, daemon, ping, status).
// This is the Stage 5c GREEN implementation.
package runtimeops

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// Starter is the public interface that mirrors app.starter.
type Starter interface {
	EnsureDaemon(context.Context) error
	Connect(context.Context) (*runtime.Client, error)
}

type RuntimeClient interface {
	Close() error
	Ping(context.Context) (runtime.PingResponse, error)
	Status(context.Context) (runtime.StatusResponse, error)
	LockVaultWithCause(context.Context, string) (runtime.LockVaultResponse, error)
}

// Deps bundles every external dependency the runtime subcommand handlers need.
// All fields are closure-typed so package app can wire the existing seam vars
// at call time and test overrides flow through transparently. Nil-valued closures
// are handled gracefully within each handler so that contract tests calling with
// an empty Deps{} do not panic.
type Deps struct {
	// OpenVault opens an authenticated vault handle.
	// Used by: export-backup, tui.
	OpenVault func(ctx context.Context) (*store.Handle, error)

	// NewVaultStore constructs a new vault store.
	// Used by: restore-backup.
	NewVaultStore func() (*store.Store, error)

	// NewStarter constructs a runtime Starter.
	// Used by: daemon, ping, status.
	NewStarter func() (Starter, error)

	// TerminalColumns returns the current terminal width.
	// Used by: status → renderStatusHuman.
	TerminalColumns func() int

	// RenderJSONOrHuman emits JSON or human-readable output.
	RenderJSONOrHuman func(ctx context.Context, stdout io.Writer, jsonOutput bool, payload any, human func(io.Writer) error) error

	// WriteJSONResponse marshals payload as JSON and writes it.
	WriteJSONResponse func(w io.Writer, payload any) error

	// RenderBackupResult renders the human-readable backup export/restore result.
	RenderBackupResult func(out io.Writer, title string, lead string, path string, checkpoint store.AuditCheckpoint) error

	// RenderStatusHuman renders the daemon status in human-readable form.
	RenderStatusHuman func(stdout io.Writer, reply runtime.StatusResponse, terminalColumns func() int) error

	// RenderPingJSONOrHuman renders a ping response in JSON or human form.
	RenderPingJSONOrHuman func(ctx context.Context, stdout io.Writer, jsonOutput bool, reply runtime.PingResponse) error

	// RenderNotRunning writes the canonical "daemon not running" response.
	RenderNotRunning func(stdout io.Writer, jsonOutput bool) error

	// ConnectIfRunning attempts to connect to the daemon without starting it.
	// Returns nil (not an error) when not running.
	ConnectIfRunning func(ctx context.Context, s Starter) RuntimeClient

	// EnsureProjectBinding ensures a project binding exists for a root.
	// Used by: tui.
	// Returns (binding, visibleRefs, autoCreated, error).
	EnsureProjectBinding func(ctx context.Context, handle *store.Handle, root string) (store.Binding, []store.VisibleReference, bool, error)

	// ReadPassphrase reads a passphrase from stdin, fd, or env.
	ReadPassphrase func(stdinFlag bool, fdFlag int, envFallback string, envName string) (string, error)

	// ExpandUserPath expands ~ in a path.
	ExpandUserPath func(path string) (string, error)

	// LoadMasterPassword reads the master password from the environment.
	LoadMasterPassword func() (string, error)

	// IsHelpArg reports whether value is a recognised help-flag spelling.
	IsHelpArg func(value string) bool

	// PrintHelpTopic emits the help topic for args to w.
	PrintHelpTopic func(w io.Writer, args []string) error

	// GlobalJSON reports whether the global --json flag is set.
	GlobalJSON func(ctx context.Context) bool

	// ErrArgvPassphrase is the error returned when passphrase is supplied via argv.
	ErrArgvPassphrase error

	// ErrArgvMasterPassword is the error returned when master-password is supplied via argv.
	ErrArgvMasterPassword error

	// NewRuntimeManager constructs a runtime.Manager for daemon subcommands.
	// When nil, runtime.NewManager() is called directly.
	NewRuntimeManager func() (*runtime.Manager, error)

	// NewInternalError wraps a message in an internal-code structured error.
	// Used by daemon stop when the process is already finished. When nil,
	// a plain fmt.Errorf is used (suitable for all non-JSON contexts).
	NewInternalError func(msg string) error

	// HTTPKeyring returns the keyring used by daemon http-key commands.
	HTTPKeyring func() store.Keyring

	// ApproveHMACKeyReinitialize gates local HMAC pairing rotation.
	ApproveHMACKeyReinitialize func() error
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

// RuntimeCommand is the top-level dispatcher for the runtime commands
// (export-backup, restore-backup, tui, daemon, ping, status).
func RuntimeCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown command")
	}
	switch args[0] {
	case "export-backup":
		return exportBackup(ctx, deps, args[1:], stdin, stdout)
	case "restore-backup":
		return restoreBackup(ctx, deps, args[1:], stdin, stdout)
	case "tui":
		return tuiHandler(ctx, deps, args[1:], stdout, stderr)
	case "daemon":
		return daemonHandler(ctx, deps, args[1:], stdout, stderr)
	case "ping":
		return pingHandler(ctx, deps, args[1:], stdout)
	case "status":
		return statusHandler(ctx, deps, args[1:], stdout)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
