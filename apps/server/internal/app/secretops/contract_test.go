package secretops_test

// hasp-wvse Stage 2 RED: contract tests for secretops.
//
// These tests FAIL on main because SecretCommand and Deps do not exist yet.
// They will PASS after the GREEN team lands internal/app/secretops/.
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

	"github.com/gethasp/hasp/apps/server/internal/app/secretops"
)

// ── Compile-time signature contract ──────────────────────────────────────────
//
// If secretops.SecretCommand does not exist, or has a different signature,
// this var declaration will produce a compile error — intentionally RED.

var _ func(ctx context.Context, deps secretops.Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error = secretops.SecretCommand

// ── Deps field contract ───────────────────────────────────────────────────────

func TestDepsHasRequiredFields(t *testing.T) {
	required := []string{
		"OpenVault",
		"ClipboardCopy",
		"UpsertItem",
		"GetItem",
		"DeleteItem",
		"ListItems",
		"BindItemAlias",
		"HideItemFromProject",
		"ItemExposures",
		"RevokeGrantsForItem",
		"IsCharDevice",
		"RevealIsTTY",
		"Getwd",
		"CanonicalProjectRoot",
		"ResolveBindingView",
	}
	typ := reflect.TypeOf(secretops.Deps{})
	for _, name := range required {
		_, ok := typ.FieldByName(name)
		if !ok {
			t.Errorf("secretops.Deps is missing required field %q — GREEN team must add it", name)
		}
	}
}

// ── Behaviour: help ───────────────────────────────────────────────────────────

func TestSecretCommandHelp(t *testing.T) {
	var out bytes.Buffer
	err := secretops.SecretCommand(context.Background(), secretops.Deps{}, []string{"help"}, strings.NewReader(""), &out, io.Discard)
	if err != nil {
		t.Fatalf("SecretCommand(help) returned error %v; want nil", err)
	}
	if out.Len() == 0 {
		t.Fatal("SecretCommand(help) wrote nothing to stdout; expected secret help text")
	}
}

// ── Behaviour: unknown subcommand ─────────────────────────────────────────────

func TestSecretCommandUnknownSubcommand(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := secretops.SecretCommand(context.Background(), secretops.Deps{}, []string{"unknown-subcommand-xyzzy"}, strings.NewReader(""), &out, &errOut)
	if err == nil {
		t.Fatal("SecretCommand(unknown-subcommand-xyzzy) returned nil; want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown secret subcommand") && !strings.Contains(msg, "did you mean") {
		t.Errorf("error message %q does not contain 'unknown secret subcommand' or 'did you mean'", msg)
	}
}

// ── Behaviour: every known subcommand is reachable via --help ─────────────────
//
// For each subcommand, call SecretCommand(ctx, deps, [name, "--help"], ...).
// Acceptable outcomes:
//   a) returns nil and writes non-empty help text mentioning the subcommand, OR
//   b) returns any non-nil error (flag parse fail is fine as long as no panic).
//
// A panic is the only unacceptable outcome.

func TestSecretCommandSubcommandsReachable(t *testing.T) {
	subcommands := []string{
		"add", "update", "rotate", "delete", "get", "show",
		"reveal", "copy", "list", "search", "diff", "expose", "hide",
	}
	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("SecretCommand(%q --help) panicked: %v", sub, r)
				}
			}()
			var out bytes.Buffer
			secretops.SecretCommand(context.Background(), secretops.Deps{}, []string{sub, "--help"}, strings.NewReader(""), &out, io.Discard) //nolint:errcheck
			// We do not fail on error — parse-fail is acceptable.
			// We only verify no panic (via recover above).
		})
	}
}
