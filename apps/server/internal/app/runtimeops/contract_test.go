package runtimeops_test

// RED-TEAM-ONLY: Do not modify this file during GREEN implementation except
// to create the package that satisfies the pinned contract. Any weakening of
// the pinned field list or function signature requires explicit RED-team sign-off.
//
// hasp-1mvx Stage 5c RED: contract tests for runtimeops.
//
// These tests FAIL on main because RuntimeCommand and Deps do not exist yet.
// They will PASS after the GREEN team lands internal/app/runtimeops/.
//
// The compile-time assertion at the top of the file is the primary RED
// signal: the file will not compile until the package exposes the exact
// symbols and signature required.

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/runtimeops"
)

// ── Compile-time signature contract ──────────────────────────────────────────
//
// If runtimeops.RuntimeCommand does not exist, or has a different signature,
// this var declaration will produce a compile error — intentionally RED.

var _ func(ctx context.Context, deps runtimeops.Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error = runtimeops.RuntimeCommand

// ── Deps field contract ───────────────────────────────────────────────────────
//
// These are the seam closure fields that correspond to the package-level vars
// in runtime_commands.go used by the 6 handler groups in scope. Each must
// become a named field on runtimeops.Deps. Field names map to seam vars as
// follows:
//
//	openVaultHandleFn   → OpenVault       (exportBackupCommand, tuiCommand)
//	newVaultStoreFn     → NewVaultStore   (restoreBackupCommand)
//	newRuntimeStarterFn → NewStarter      (daemonCommand, pingCommand, statusCommand)
//	terminalColumnsFn   → TerminalColumns (statusCommand → renderStatusHuman)
//
// Note on Starter: runtimeops defines its own Starter interface (mirroring
// app.starter) so the package has no import cycle back to package app.
// Package app's *runtimeStarter satisfies runtimeops.Starter via structural
// typing, exactly as agentops.Starter mirrors app.starter.

func TestDepsHasRequiredFields(t *testing.T) {
	required := []string{
		"OpenVault",
		"NewVaultStore",
		"NewStarter",
		"TerminalColumns",
	}
	typ := reflect.TypeOf(runtimeops.Deps{})
	for _, name := range required {
		_, ok := typ.FieldByName(name)
		if !ok {
			t.Errorf("runtimeops.Deps is missing required field %q — GREEN team must add it", name)
		}
	}
}

// TestDepsFieldsAreClosures verifies that the required fields are all function
// types (closures), not plain values. A non-func field would indicate a
// structural mistake in the Deps definition.
func TestDepsFieldsAreClosures(t *testing.T) {
	funcFields := []string{
		"OpenVault",
		"NewVaultStore",
		"NewStarter",
		"TerminalColumns",
	}
	typ := reflect.TypeOf(runtimeops.Deps{})
	for _, name := range funcFields {
		f, ok := typ.FieldByName(name)
		if !ok {
			// Already caught by TestDepsHasRequiredFields; skip here.
			continue
		}
		if f.Type.Kind() != reflect.Func {
			t.Errorf("runtimeops.Deps.%s has kind %s; want func", name, f.Type.Kind())
		}
	}
}

// ── Behaviour: every known subcommand is reachable via --help ─────────────────
//
// For each top-level subcommand routed through RuntimeCommand, call with
// [sub, "--help"] and recover panics. These are not grouped under a shared
// parent sub-group (unlike agent/secret), so there is no meaningful "help"
// topic at the RuntimeCommand level itself. Instead we pin each individual
// sub-entry-point.
//
// Acceptable outcomes per sub:
//
//	a) returns nil and writes non-empty output, OR
//	b) returns any non-nil error (parse fail is fine as long as no panic).
//
// A panic is the only unacceptable outcome.
func TestRuntimeCommandSubcommandsReachable(t *testing.T) {
	subcommands := []string{
		"export-backup",
		"restore-backup",
		"tui",
		"daemon",
		"ping",
		"status",
	}
	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("RuntimeCommand(%q --help) panicked: %v", sub, r)
				}
			}()
			var out bytes.Buffer
			runtimeops.RuntimeCommand(context.Background(), runtimeops.Deps{}, []string{sub, "--help"}, strings.NewReader(""), &out, io.Discard) //nolint:errcheck
			// We do not fail on error — parse-fail is acceptable.
			// We only verify no panic (via recover above).
		})
	}
}

// ── Behaviour: unknown command ────────────────────────────────────────────────
//
// RuntimeCommand dispatches top-level commands (not a subcommand group), so
// the error sentinel phrase follows the pattern in app.go: "unknown command".

func TestRuntimeCommandUnknownSubcommand(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runtimeops.RuntimeCommand(context.Background(), runtimeops.Deps{}, []string{"unknown-command-xyzzy"}, strings.NewReader(""), &out, &errOut)
	if err == nil {
		t.Fatal("RuntimeCommand(unknown-command-xyzzy) returned nil; want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown") {
		t.Errorf("error message %q does not contain 'unknown'", msg)
	}
}
