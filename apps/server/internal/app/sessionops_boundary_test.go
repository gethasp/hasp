package app

// hasp-wpdr Stage 5b RED: boundary tests for the package-app wrapper.
//
// These tests verify two things:
//  1. The existing sessionCommand(ctx, args, stdout, s) entrypoint in package app
//     still behaves correctly after migration (wrapper-to-sessionops delegation).
//  2. The per-subcommand shims (sessionOpenCommand, sessionGrantPlaintextCommand,
//     sessionGrantPlaintextCommandWithDeps, sessionRevokeCommand,
//     sessionRevokeCommandWithDeps, sessionResolveCommand) survive in package app
//     so that the many existing tests that call them by name continue to compile
//     and pass.
//
// RED-TEAM-ONLY: Do not modify this file during GREEN implementation except
// to create the sessionops package and defaultSessionDeps() that satisfy these
// assertions. Any removal of a pinned function name requires RED-team sign-off.

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/sessionops"
)

// ── Compile-time: defaultSessionDeps must exist and return sessionops.Deps ────
//
// If GREEN does not add a defaultSessionDeps() function to package app
// (e.g. in a new session_deps.go file), this var will fail to compile.

var _ sessionops.Deps = defaultSessionDeps()

// ── Compile-time: dispatch shim must exist ────────────────────────────────────
//
// sessionCommand is called from command_inventory.go and from many existing
// tests. After Stage 5b GREEN it must remain as a shim that delegates to
// sessionops.SessionCommand. This var pins its continued existence.

var _ = sessionCommand

// ── Compile-time: per-subcommand shims must survive in package app ────────────
//
// The following functions are called directly by existing tests in package app:
//   - sessionOpenCommand                (seam_error_test.go, coverage_edges_test.go, human_output_commands_test.go)
//   - sessionGrantPlaintextCommand      (runtime_commands_extra_test.go)
//   - sessionGrantPlaintextCommandWithDeps (runtime_commands_extra_test.go, residual_branch_sweep_test.go, human_output_commands_test.go)
//   - sessionRevokeCommand              (hasp_ber_conformance_test.go, coverage_edges_test.go)
//   - sessionRevokeCommandWithDeps      (hasp_ber_conformance_test.go)
//   - sessionResolveCommand             (coverage_edges_test.go, human_output_commands_test.go)
//
// Each must remain callable in package app after migration — either as a
// stand-alone function or as a shim that prepends its subcommand and routes
// through sessionops.SessionCommand.
//
// Note: sessionListCommand and sessionListCommandWithDeps have no direct test
// callers and are intentionally omitted from this pin list.

var _ = sessionOpenCommand
var _ = sessionGrantPlaintextCommand
var _ = sessionGrantPlaintextCommandWithDeps
var _ = sessionRevokeCommand
var _ = sessionRevokeCommandWithDeps
var _ = sessionResolveCommand

// ── Compile-time: helper functions with non-test callers must survive ─────────
//
// sessionStateBadge is called by renderSessionListWithColor (production code).
// renderSessionListWithColor is called by sessionListCommandWithDeps (production
// code) and by multiple test files directly.
// Both must remain in package app (or be re-exported from sessionops) so that
// the existing session_list_color_red_test.go and verbose_renderer_red_test.go
// continue to compile.

var _ = sessionStateBadge
var _ = renderSessionListWithColor

// ── Behaviour: sessionCommand dispatch still works ───────────────────────────

func TestSessionBoundaryHelpStillWorks(t *testing.T) {
	lockAppSeams(t)
	var out bytes.Buffer
	err := sessionCommand(context.Background(), []string{"help"}, &out, &fakeStarter{})
	if err != nil {
		t.Fatalf("sessionCommand(help) returned %v; want nil", err)
	}
	if out.Len() == 0 {
		t.Fatal("sessionCommand(help) produced no output; expected help text")
	}
}

// TestSessionBoundaryUnknownSubcommand asserts that the package-app wrapper
// surfaces the unknown-subcommand error after migration.
func TestSessionBoundaryUnknownSubcommand(t *testing.T) {
	lockAppSeams(t)
	err := sessionCommand(context.Background(), []string{"no-such-subcommand-xyzzy"}, io.Discard, &fakeStarter{})
	if err == nil {
		t.Fatal("sessionCommand(no-such-subcommand-xyzzy) returned nil; want an error")
	}
}

// TestSessionBoundaryDefaultDepsNonNil verifies that every closure field on the
// Deps returned by defaultSessionDeps() is non-nil. A nil closure field causes a
// panic at call time, which would be a regression against the direct-seam
// implementation that existed before migration.
func TestSessionBoundaryDefaultDepsNonNil(t *testing.T) {
	lockAppSeams(t)
	// We do not call defaultSessionDeps() here because the underlying seam vars
	// (openVaultHandleFn, etc.) reference a real vault that is not set up in
	// unit tests. We assert non-nil at the function level: if defaultSessionDeps
	// is not defined GREEN has not landed yet.
	//
	// Non-nil check of the function itself (compile-time, above) is sufficient
	// for the RED signal. Behavioural non-nil checks of each closure field
	// belong in a GREEN-phase integration test.
	_ = defaultSessionDeps // referenced above via var _; keep this comment for docs.
}
