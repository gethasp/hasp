package appops_test

// hasp-0r88 Stage 4 RED: contract tests for appops.
//
// These tests FAIL on main because AppCommand and Deps do not exist yet.
// They will PASS after the GREEN team lands internal/app/appops/.
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

	"github.com/gethasp/hasp/apps/server/internal/app/appops"
)

// ── Compile-time signature contract ──────────────────────────────────────────
//
// If appops.AppCommand does not exist, or has a different signature,
// this var declaration will produce a compile error — intentionally RED.

var _ func(ctx context.Context, deps appops.Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error = appops.AppCommand

// ── Deps field contract ───────────────────────────────────────────────────────
//
// These are the 14 seam closure fields that correspond to the package-level
// vars in app_consumers.go. Each must become a named field on appops.Deps.
// Field names map to seam vars as follows:
//
//	appResolvePathsFn    → AppResolvePaths
//	appWriteFileFn       → AppWriteFile
//	appReadFileFn        → AppReadFile
//	appMkdirAllFn        → AppMkdirAll
//	appRemoveFn          → AppRemove
//	appUserShellFn       → AppUserShell
//	appCurrentShellFn    → AppCurrentShell
//	appUserHomeDirFn     → AppUserHomeDir
//	storeGetAppFn        → StoreGetApp
//	storeListAppsFn      → StoreListApps
//	storeUpsertAppFn     → StoreUpsertApp
//	storeDeleteAppFn     → StoreDeleteApp
//	appExecuteConsumerFn → AppExecuteConsumer
//	appInstallLauncherFn → AppInstallLauncher

func TestDepsHasRequiredFields(t *testing.T) {
	required := []string{
		"AppResolvePaths",
		"AppWriteFile",
		"AppReadFile",
		"AppMkdirAll",
		"AppRemove",
		"AppUserShell",
		"AppCurrentShell",
		"AppUserHomeDir",
		"StoreGetApp",
		"StoreListApps",
		"StoreUpsertApp",
		"StoreDeleteApp",
		"AppExecuteConsumer",
		"AppInstallLauncher",
	}
	typ := reflect.TypeOf(appops.Deps{})
	for _, name := range required {
		_, ok := typ.FieldByName(name)
		if !ok {
			t.Errorf("appops.Deps is missing required field %q — GREEN team must add it", name)
		}
	}
}

// TestDepsFieldsAreClosures verifies that the required fields are all function
// types (closures), not plain values. A non-func field would indicate a
// structural mistake in the Deps definition.
func TestDepsFieldsAreClosures(t *testing.T) {
	funcFields := []string{
		"AppResolvePaths",
		"AppWriteFile",
		"AppReadFile",
		"AppMkdirAll",
		"AppRemove",
		"AppUserShell",
		"AppCurrentShell",
		"AppUserHomeDir",
		"StoreGetApp",
		"StoreListApps",
		"StoreUpsertApp",
		"StoreDeleteApp",
		"AppExecuteConsumer",
		"AppInstallLauncher",
	}
	typ := reflect.TypeOf(appops.Deps{})
	for _, name := range funcFields {
		f, ok := typ.FieldByName(name)
		if !ok {
			// Already caught by TestDepsHasRequiredFields; skip here.
			continue
		}
		if f.Type.Kind() != reflect.Func {
			t.Errorf("appops.Deps.%s has kind %s; want func", name, f.Type.Kind())
		}
	}
}

// ── Behaviour: help ───────────────────────────────────────────────────────────

func TestAppCommandHelp(t *testing.T) {
	var out bytes.Buffer
	err := appops.AppCommand(context.Background(), appops.Deps{}, []string{"help"}, strings.NewReader(""), &out, io.Discard)
	if err != nil {
		t.Fatalf("AppCommand(help) returned error %v; want nil", err)
	}
	if out.Len() == 0 {
		t.Fatal("AppCommand(help) wrote nothing to stdout; expected app help text")
	}
}

// ── Behaviour: unknown subcommand ─────────────────────────────────────────────

func TestAppCommandUnknownSubcommand(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := appops.AppCommand(context.Background(), appops.Deps{}, []string{"unknown-subcommand-xyzzy"}, strings.NewReader(""), &out, &errOut)
	if err == nil {
		t.Fatal("AppCommand(unknown-subcommand-xyzzy) returned nil; want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown app subcommand") {
		t.Errorf("error message %q does not contain 'unknown app subcommand'", msg)
	}
}

// ── Behaviour: every known subcommand is reachable via --help ─────────────────
//
// For each subcommand, call AppCommand(ctx, deps, [name, "--help"], ...).
// Acceptable outcomes:
//
//	a) returns nil and writes non-empty help text, OR
//	b) returns any non-nil error (parse fail is fine as long as no panic).
//
// A panic is the only unacceptable outcome.
func TestAppCommandSubcommandsReachable(t *testing.T) {
	subcommands := []string{
		"connect", "run", "shell", "install", "disconnect", "list",
	}
	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("AppCommand(%q --help) panicked: %v", sub, r)
				}
			}()
			var out bytes.Buffer
			appops.AppCommand(context.Background(), appops.Deps{}, []string{sub, "--help"}, strings.NewReader(""), &out, io.Discard) //nolint:errcheck
			// We do not fail on error — parse-fail is acceptable.
			// We only verify no panic (via recover above).
		})
	}
}
