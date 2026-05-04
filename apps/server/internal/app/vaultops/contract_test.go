package vaultops_test

// hasp-htiz Stage 5a RED: contract tests for vaultops.
//
// These tests FAIL on main because VaultCommand, Deps, and GrantOpsDeps do not
// exist yet. They will PASS after the GREEN team lands internal/app/vaultops/.
//
// The compile-time assertion at the top of the file is the primary RED
// signal: the file will not compile until the package exposes the exact
// symbols and signature required.
//
// RED-TEAM-ONLY: Do not modify this file during GREEN implementation except
// to create the package that satisfies the pinned contract. Any weakening
// of the pinned field list or function signature requires explicit RED-team
// sign-off.

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/vaultops"
)

// ── Compile-time signature contract ──────────────────────────────────────────
//
// If vaultops.VaultCommand does not exist, or has a different signature,
// this var declaration will produce a compile error — intentionally RED.

var _ func(ctx context.Context, deps vaultops.Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error = vaultops.VaultCommand

// ── Compile-time: GrantOpsDeps must be an exported struct ─────────────────────
//
// sessionops (Stage 5b) imports vaultops.GrantOpsDeps to wire the session
// revoke --all handler, which shares the same RevokeAllGrants /
// DisableConvenienceUnlock seams as vault-lock and vault forget-device.
// This line fails to compile if GREEN does not export the type.

var _ vaultops.GrantOpsDeps = vaultops.GrantOpsDeps{}

// ── Deps field contract ───────────────────────────────────────────────────────
//
// These are the seam closure fields derived from the handler implementations in
// apps/server/internal/app/runtime_commands.go. Each must become a named
// field on vaultops.Deps. Field names map to seam vars as follows:
//
//	openVaultHandleFn   → OpenVaultHandle   (used by: rekey, rekdf, lock, forget-device)
//
// The starter interface is threaded through the vault-lock handler (to reach
// the runtime daemon for session revocation), so it becomes a closure field:
//
//	newRuntimeStarterFn → NewStarter         (used by: lock — needs s starter to call LockVault)
//
// The RevokeAllGrants and DisableConvenienceUnlock operations from
// vaultGrantOpsDeps are bundled into GrantOpsDeps (see below) rather than
// placed directly on Deps; VaultCommand receives them via GrantOpsDeps.

func TestDepsHasRequiredFields(t *testing.T) {
	required := []string{
		"OpenVaultHandle",
		"NewStarter",
	}
	typ := reflect.TypeOf(vaultops.Deps{})
	for _, name := range required {
		_, ok := typ.FieldByName(name)
		if !ok {
			t.Errorf("vaultops.Deps is missing required field %q — GREEN team must add it", name)
		}
	}
}

// TestDepsFieldsAreClosures verifies that the required fields are all function
// types (closures), not plain values. A non-func field would indicate a
// structural mistake in the Deps definition.
func TestDepsFieldsAreClosures(t *testing.T) {
	funcFields := []string{
		"OpenVaultHandle",
		"NewStarter",
	}
	typ := reflect.TypeOf(vaultops.Deps{})
	for _, name := range funcFields {
		f, ok := typ.FieldByName(name)
		if !ok {
			// Already caught by TestDepsHasRequiredFields; skip here.
			continue
		}
		if f.Type.Kind() != reflect.Func {
			t.Errorf("vaultops.Deps.%s has kind %s; want func", name, f.Type.Kind())
		}
	}
}

// ── Behaviour: help ───────────────────────────────────────────────────────────

func TestVaultCommandHelp(t *testing.T) {
	var out bytes.Buffer
	err := vaultops.VaultCommand(context.Background(), vaultops.Deps{}, []string{"help"}, strings.NewReader(""), &out, io.Discard)
	if err != nil {
		t.Fatalf("VaultCommand(help) returned error %v; want nil", err)
	}
	if out.Len() == 0 {
		t.Fatal("VaultCommand(help) wrote nothing to stdout; expected vault help text")
	}
}

// ── Behaviour: unknown subcommand ─────────────────────────────────────────────

func TestVaultCommandUnknownSubcommand(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := vaultops.VaultCommand(context.Background(), vaultops.Deps{}, []string{"unknown-subcommand-xyzzy"}, strings.NewReader(""), &out, &errOut)
	if err == nil {
		t.Fatal("VaultCommand(unknown-subcommand-xyzzy) returned nil; want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown vault subcommand") {
		t.Errorf("error message %q does not contain 'unknown vault subcommand'", msg)
	}
}

// ── Behaviour: every known subcommand is reachable via --help ─────────────────
//
// For each subcommand, call VaultCommand(ctx, deps, [name, "--help"], ...).
// Acceptable outcomes:
//
//	a) returns nil and writes non-empty help text, OR
//	b) returns any non-nil error (parse fail is fine as long as no panic).
//
// A panic is the only unacceptable outcome.
func TestVaultCommandSubcommandsReachable(t *testing.T) {
	subcommands := []string{
		"rekey", "rekdf", "lock", "forget-device",
	}
	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("VaultCommand(%q --help) panicked: %v", sub, r)
				}
			}()
			var out bytes.Buffer
			vaultops.VaultCommand(context.Background(), vaultops.Deps{}, []string{sub, "--help"}, strings.NewReader(""), &out, io.Discard) //nolint:errcheck
			// We do not fail on error — parse-fail is acceptable.
			// We only verify no panic (via recover above).
		})
	}
}
