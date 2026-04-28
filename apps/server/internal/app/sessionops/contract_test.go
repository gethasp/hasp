package sessionops_test

// hasp-wpdr Stage 5b RED: contract tests for sessionops.
//
// These tests FAIL on main because SessionCommand and Deps do not exist yet.
// They will PASS after the GREEN team lands internal/app/sessionops/.
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

	"github.com/gethasp/hasp/apps/server/internal/app/sessionops"
	"github.com/gethasp/hasp/apps/server/internal/app/vaultops"
)

// ── Compile-time signature contract ──────────────────────────────────────────
//
// If sessionops.SessionCommand does not exist, or has a different signature,
// this var declaration will produce a compile error — intentionally RED.

var _ func(ctx context.Context, deps sessionops.Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error = sessionops.SessionCommand

// ── Cross-package coupling pins ───────────────────────────────────────────────
//
// sessionRevokeCommandWithDeps takes a vaultGrantOpsDeps (Stage 5a exports this
// as vaultops.GrantOpsDeps). This pin verifies the cross-package import works.
// LocalDeps is the exported form of sessionLocalDeps.
// ConfirmPlaintextGrantDeps is the exported form of confirmPlaintextGrantDeps.

var _ vaultops.GrantOpsDeps = vaultops.GrantOpsDeps{}
var _ sessionops.LocalDeps = sessionops.LocalDeps{}
var _ sessionops.ConfirmPlaintextGrantDeps = sessionops.ConfirmPlaintextGrantDeps{}

// ── Deps field contract ───────────────────────────────────────────────────────
//
// These are the closure fields that correspond to the seam Fn vars and
// internal helpers the session handlers in runtime_commands.go need.
// Each must become a named field on sessionops.Deps.
// Field names map to seam vars / helpers as follows:
//
//	openVaultHandleFn                → OpenVault
//	appCanonicalProjectRootFn        → CanonicalProjectRoot
//	ensureProjectBinding (internal)  → EnsureProjectBinding
//	secretGetItemFn                  → GetItem
//	newRuntimeStarterFn              → NewStarter
//	renderJSONOrHuman                → RenderJSONOrHuman
//	renderSimpleAction               → RenderSimpleAction
//	isHelpArg                        → IsHelpArg
//	printHelpTopic                   → PrintHelpTopic
//	globalFlagsFromContext (json)    → GlobalJSON

func TestDepsHasRequiredFields(t *testing.T) {
	required := []string{
		"OpenVault",
		"CanonicalProjectRoot",
		"EnsureProjectBinding",
		"GetItem",
		"NewStarter",
		"RenderJSONOrHuman",
		"RenderSimpleAction",
		"IsHelpArg",
		"PrintHelpTopic",
		"GlobalJSON",
	}
	typ := reflect.TypeOf(sessionops.Deps{})
	for _, name := range required {
		_, ok := typ.FieldByName(name)
		if !ok {
			t.Errorf("sessionops.Deps is missing required field %q — GREEN team must add it", name)
		}
	}
}

// TestDepsFieldsAreClosures verifies that the required fields are all function
// types (closures), not plain values. A non-func field would indicate a
// structural mistake in the Deps definition.
func TestDepsFieldsAreClosures(t *testing.T) {
	funcFields := []string{
		"OpenVault",
		"CanonicalProjectRoot",
		"EnsureProjectBinding",
		"GetItem",
		"NewStarter",
		"RenderJSONOrHuman",
		"RenderSimpleAction",
		"IsHelpArg",
		"PrintHelpTopic",
		"GlobalJSON",
	}
	typ := reflect.TypeOf(sessionops.Deps{})
	for _, name := range funcFields {
		f, ok := typ.FieldByName(name)
		if !ok {
			// Already caught by TestDepsHasRequiredFields; skip here.
			continue
		}
		if f.Type.Kind() != reflect.Func {
			t.Errorf("sessionops.Deps.%s has kind %s; want func", name, f.Type.Kind())
		}
	}
}

// ── Behaviour: help ───────────────────────────────────────────────────────────

func TestSessionCommandHelp(t *testing.T) {
	var out bytes.Buffer
	err := sessionops.SessionCommand(context.Background(), sessionops.Deps{}, []string{"help"}, strings.NewReader(""), &out, io.Discard)
	if err != nil {
		t.Fatalf("SessionCommand(help) returned error %v; want nil", err)
	}
	if out.Len() == 0 {
		t.Fatal("SessionCommand(help) wrote nothing to stdout; expected session help text")
	}
}

// ── Behaviour: unknown subcommand ─────────────────────────────────────────────

func TestSessionCommandUnknownSubcommand(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := sessionops.SessionCommand(context.Background(), sessionops.Deps{}, []string{"unknown-subcommand-xyzzy"}, strings.NewReader(""), &out, &errOut)
	if err == nil {
		t.Fatal("SessionCommand(unknown-subcommand-xyzzy) returned nil; want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown session subcommand") {
		t.Errorf("error message %q does not contain 'unknown session subcommand'", msg)
	}
}

// ── Behaviour: every known subcommand is reachable via --help ─────────────────
//
// For each subcommand, call SessionCommand(ctx, deps, [name, "--help"], ...).
// Acceptable outcomes:
//
//	a) returns nil and writes non-empty help text, OR
//	b) returns any non-nil error (parse fail is fine as long as no panic).
//
// A panic is the only unacceptable outcome.
func TestSessionCommandSubcommandsReachable(t *testing.T) {
	subcommands := []string{
		"open", "grant-plaintext", "revoke", "list", "resolve",
	}
	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("SessionCommand(%q --help) panicked: %v", sub, r)
				}
			}()
			var out bytes.Buffer
			sessionops.SessionCommand(context.Background(), sessionops.Deps{}, []string{sub, "--help"}, strings.NewReader(""), &out, io.Discard) //nolint:errcheck
			// We do not fail on error — parse-fail is acceptable.
			// We only verify no panic (via recover above).
		})
	}
}
