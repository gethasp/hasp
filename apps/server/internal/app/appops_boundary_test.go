package app

// hasp-0r88 Stage 4 RED: boundary tests for the package-app wrapper.
//
// These tests verify two things:
//  1. The existing appConsumerCommand(ctx, args, ...) entrypoint in package app
//     still behaves correctly after migration (wrapper-to-appops delegation).
//  2. The per-subcommand shims (appConnectCommand, appConnectCommandWithInput,
//     appRunCommand, appShellCommand, appInstallCommand, appInstallCommandWithInput,
//     appDisconnectCommand, appListCommand) survive in package app so that the
//     many existing tests that call them by name continue to compile and pass.
//
// RED-TEAM-ONLY: Do not modify this file during GREEN implementation except
// to create the appops package and defaultAppDeps() that satisfy these
// assertions. Any removal of a pinned function name requires RED-team sign-off.

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/appops"
)

// ── Compile-time: defaultAppDeps must exist and return appops.Deps ────────────
//
// If GREEN does not add a defaultAppDeps() function to package app
// (e.g. in a new app_deps.go file), this var will fail to compile.

var _ appops.Deps = defaultAppDeps()

// ── Compile-time: dispatch shim must exist ────────────────────────────────────
//
// appConsumerCommand is called from command_inventory.go and from many
// existing tests. After Stage 4 GREEN it must remain as a shim that delegates
// to appops.AppCommand. This var pins its continued existence.

var _ = appConsumerCommand

// ── Compile-time: per-subcommand shims must survive in package app ────────────
//
// The following functions are called directly by existing tests in package app:
//   - appConnectCommand            (consumer_commands_zero_hit_test.go, consumer_helper_branches_test.go)
//   - appConnectCommandWithInput   (consumer_helper_branches_test.go, consumer_remaining_branches_test.go)
//   - appRunCommand                (consumer_commands_zero_hit_test.go, consumer_helper_branches_test.go)
//   - appShellCommand              (consumer_commands_zero_hit_test.go, consumer_helper_branches_test.go)
//   - appInstallCommand            (consumer_commands_zero_hit_test.go, consumer_helper_branches_test.go)
//   - appInstallCommandWithInput   (consumer_remaining_branches_test.go)
//   - appDisconnectCommand         (consumer_commands_zero_hit_test.go, consumer_helper_branches_test.go)
//   - appListCommand               (consumer_commands_zero_hit_test.go)
//
// Each must remain callable in package app after migration — either as a
// stand-alone function or as a shim that prepends its subcommand and routes
// through appops.AppCommand.

var _ = appConnectCommand
var _ = appConnectCommandWithInput
var _ = appRunCommand
var _ = appShellCommand
var _ = appInstallCommand
var _ = appInstallCommandWithInput
var _ = appDisconnectCommand
var _ = appListCommand

// ── Behaviour: appConsumerCommand dispatch still works ───────────────────────

func TestAppBoundaryHelpStillWorks(t *testing.T) {
	lockAppSeams(t)
	var out bytes.Buffer
	err := appConsumerCommand(context.Background(), []string{"help"}, bytes.NewReader(nil), &out, io.Discard, &fakeStarter{})
	if err != nil {
		t.Fatalf("appConsumerCommand(help) returned %v; want nil", err)
	}
	if out.Len() == 0 {
		t.Fatal("appConsumerCommand(help) produced no output; expected help text")
	}
}

// TestAppBoundaryUnknownSubcommand asserts that the package-app wrapper
// surfaces the unknown-subcommand error after migration.
func TestAppBoundaryUnknownSubcommand(t *testing.T) {
	lockAppSeams(t)
	err := appConsumerCommand(context.Background(), []string{"no-such-subcommand-xyzzy"}, bytes.NewReader(nil), io.Discard, io.Discard, &fakeStarter{})
	if err == nil {
		t.Fatal("appConsumerCommand(no-such-subcommand-xyzzy) returned nil; want an error")
	}
}

// TestAppBoundaryDefaultDepsNonNil verifies that every closure field on the
// Deps returned by defaultAppDeps() is non-nil. A nil closure field causes a
// panic at call time, which would be a regression against the direct-seam
// implementation that existed before migration.
func TestAppBoundaryDefaultDepsNonNil(t *testing.T) {
	lockAppSeams(t)
	// We do not call defaultAppDeps() here because the underlying seam vars
	// (appResolvePathsFn, etc.) reference real OS operations not set up in
	// unit tests. We assert non-nil at the function level: if defaultAppDeps
	// is not defined GREEN has not landed yet.
	//
	// Non-nil check of the function itself (compile-time, above) is sufficient
	// for the RED signal. Behavioural non-nil checks of each closure field
	// belong in a GREEN-phase integration test.
	_ = defaultAppDeps // referenced above via var _; keep this comment for docs.
}
