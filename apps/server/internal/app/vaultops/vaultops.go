// Package vaultops implements the `hasp vault` subcommand handlers.
// It is structurally parallel to the other ops packages: every external
// dependency is injected through a Deps closure so that package app can
// wire the existing seam vars at call time and test overrides propagate
// transparently.
package vaultops

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// Starter is the public interface that mirrors app.starter.
// Package app's *runtimeStarter satisfies this interface via structural typing.
// Only Connect is required because vault lock calls LockVault on an existing
// client after attempting to connect without starting the daemon.
type Starter interface {
	Connect(context.Context) (*runtime.Client, error)
}

// GrantOpsDeps bundles the store-handle operations that vault-lock,
// vault forget-device, and session revoke --all (Stage 5b) need to drop
// saved grants and convenience unlock state. It is exported so that
// sessionops (Stage 5b) can import and reuse it for session revoke --all.
type GrantOpsDeps struct {
	RevokeAllGrants          func(handle *store.Handle) (int, error)
	DisableConvenienceUnlock func(handle *store.Handle, ctx context.Context) (bool, error)
}

// Deps bundles every external dependency the vault subcommand handlers need.
// All fields are closure-typed so package app can wire the existing seam vars
// at call time and test overrides flow through transparently.
type Deps struct {
	// OpenVaultHandle opens an authenticated vault handle.
	// Used by: rekey, rekdf, lock, forget-device.
	OpenVaultHandle func(ctx context.Context) (*store.Handle, error)

	// NewStarter constructs a runtime Starter.
	// Used by: lock — needs to Connect to the daemon to revoke sessions.
	NewStarter func() (Starter, error)

	// GrantOps bundles the store-level operations shared with session revoke.
	// When nil, the handlers use defaultGrantOpsDeps().
	GrantOps func() GrantOpsDeps

	// LoadMasterPassword reads the master password from the environment.
	LoadMasterPassword func() (string, error)

	// LoadNewMasterPassword reads the new master password from the environment.
	LoadNewMasterPassword func() (string, error)

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
}

// printVaultHelp writes a minimal vault subcommand help stub used when
// deps.PrintHelpTopic is not wired.
func printVaultHelp(w io.Writer) error {
	subcommands := []string{"lock", "forget-device", "rekey", "rekdf"}
	_, err := fmt.Fprintf(w, "Usage: hasp vault <subcommand>\n\nSubcommands: %s\n", strings.Join(subcommands, ", "))
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

// VaultCommand is the top-level dispatcher for `hasp vault <subcommand>`.
func VaultCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	isHelp := deps.IsHelpArg
	if isHelp == nil {
		isHelp = isHelpArgFallback
	}
	printHelp := deps.PrintHelpTopic
	if printHelp == nil {
		printHelp = func(w io.Writer, _ []string) error {
			return printVaultHelp(w)
		}
	}
	if len(args) == 0 || isHelp(args[0]) {
		return printHelp(stdout, []string{"vault"})
	}
	switch args[0] {
	case "lock":
		return lock(ctx, deps, args[1:], stdout)
	case "forget-device":
		return forgetDevice(ctx, deps, args[1:], stdout)
	case "rekey":
		return rekey(ctx, deps, args[1:], stdout)
	case "rekdf":
		return rekdf(ctx, deps, args[1:], stdout)
	default:
		return fmt.Errorf("unknown vault subcommand %q", args[0])
	}
}
