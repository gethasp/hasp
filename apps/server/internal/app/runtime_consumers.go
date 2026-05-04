package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/runtimeops"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var appCanonicalProjectRootFn = store.CanonicalProjectRoot
var openVaultHandleFn = openVaultHandle

// ── Runtime consumer shims ────────────────────────────────────────────────────
//
// These shims preserve the package-app function signatures that existing tests
// call directly. Each one delegates to runtimeops.RuntimeCommand via
// defaultRuntimeDeps() (or a locally-customised Deps). Zero behaviour change.

func exportBackupCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return runtimeops.RuntimeCommand(ctx, defaultRuntimeDeps(), append([]string{"export-backup"}, args...), nil, stdout, io.Discard)
}

func restoreBackupCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return runtimeops.RuntimeCommand(ctx, defaultRuntimeDeps(), append([]string{"restore-backup"}, args...), nil, stdout, io.Discard)
}

func tuiCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	return runtimeops.RuntimeCommand(ctx, defaultRuntimeDeps(), append([]string{"tui"}, args...), nil, stdout, stderr)
}

// runtimeDepsWithStarter returns a defaultRuntimeDeps() with NewStarter and
// ConnectIfRunning overridden to use the supplied starter s. This lets the
// daemon/ping/status shims inject a test-supplied fakeStarter without holding
// the package-level seam mutex.
func runtimeDepsWithStarter(s starter) runtimeops.Deps {
	deps := defaultRuntimeDeps()
	if s != nil {
		deps.NewStarter = func() (runtimeops.Starter, error) { return s, nil }
		deps.ConnectIfRunning = func(ctx context.Context, _ runtimeops.Starter) *runtime.Client {
			return connectIfRunning(ctx, s)
		}
	}
	return deps
}

func daemonCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	return runtimeops.RuntimeCommand(ctx, runtimeDepsWithStarter(s), append([]string{"daemon"}, args...), nil, stdout, io.Discard)
}

func pingCommand(ctx context.Context, stdout io.Writer, s starter) error {
	return pingCommandWithArgs(ctx, nil, stdout, s)
}

func pingCommandWithArgs(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	return runtimeops.RuntimeCommand(ctx, runtimeDepsWithStarter(s), append([]string{"ping"}, args...), nil, stdout, io.Discard)
}

func statusCommand(ctx context.Context, stdout io.Writer, s starter) error {
	return statusCommandWithArgs(ctx, nil, stdout, s)
}

func statusCommandWithArgs(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	return runtimeops.RuntimeCommand(ctx, runtimeDepsWithStarter(s), append([]string{"status"}, args...), nil, stdout, io.Discard)
}

// renderStatusHuman writes the daemon status as a 2-space padded key/value
// table. Long socket paths are leading-ellipsis clipped against the live
// terminal width (hasp-hnf9) so narrow terminals don't wrap; JSON callers
// always see the full SocketPath.
//
// NOTE: This function is kept in package app (rather than moved to runtimeops)
// because daemon_status_clip_red_test.go calls it directly. The runtimeops
// RenderStatusHuman dep delegates back to this function.
func renderStatusHuman(stdout io.Writer, reply runtime.StatusResponse) error {
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	const socketKey = "socket"
	// Match the on-screen padding (key + minpad of 2) so the clip threshold
	// reflects what bytes actually print on this row.
	socketPath := clipForTerminal(reply.SocketPath, len(socketKey)+2, terminalColumnsFn())
	fmt.Fprintf(tw, "%s\t%s\n", socketKey, socketPath)
	fmt.Fprintf(tw, "pid\t%d\n", reply.PID)
	fmt.Fprintf(tw, "started_at\t%s\n", reply.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(tw, "active_sessions\t%d\n", reply.ActiveSessions)
	fmt.Fprintf(tw, "audit_degraded\t%t\n", reply.AuditDegraded)
	if reply.AuditDegradedAt != nil {
		fmt.Fprintf(tw, "audit_degraded_at\t%s\n", reply.AuditDegradedAt.Format(time.RFC3339))
	}
	fmt.Fprintf(tw, "process_identity_degraded\t%t\n", reply.ProcessIdentityDegraded)
	if reply.ProcessIdentityDegradedReason != "" {
		fmt.Fprintf(tw, "process_identity_degraded_reason\t%s\n", reply.ProcessIdentityDegradedReason)
	}
	return tw.Flush()
}

// ensureClient calls EnsureDaemon then Connect on the starter.
func ensureClient(ctx context.Context, s starter) (*runtime.Client, error) {
	if err := s.EnsureDaemon(ctx); err != nil {
		return nil, err
	}
	return s.Connect(ctx)
}

// connectIfRunning attempts to connect to the daemon without starting it.
// It returns nil (not an error) when the daemon is not listening so callers
// can render a "not running" response rather than spawning a new process.
func connectIfRunning(ctx context.Context, s starter) *runtime.Client {
	client, err := s.Connect(ctx)
	if err != nil {
		return nil
	}
	return client
}

// renderNotRunning writes the canonical "daemon not running" response in either
// human or JSON form and exits cleanly (nil error = exit 0).
func renderNotRunning(stdout io.Writer, jsonOutput bool) error {
	if jsonOutput {
		return writeJSONResponse(stdout, map[string]any{"running": false})
	}
	_, err := fmt.Fprintln(stdout, "not running")
	return err
}

func openVaultHandle(ctx context.Context) (*store.Handle, error) {
	vaultStore, err := newVaultStoreFn()
	if err != nil {
		return nil, err
	}
	password, err := loadMasterPassword()
	if err == nil {
		handle, perr := openStoreWithPasswordFn(ctx, vaultStore, password)
		if perr == nil && handle != nil {
			setAuditHMACKey(handle.AuditHMACKey())
		}
		return handle, perr
	}
	handle, unlockErr := vaultStore.OpenWithConvenienceUnlock(ctx)
	if unlockErr != nil && errors.Is(unlockErr, store.ErrKeyringUnavailable) {
		return nil, fmt.Errorf("HASP_MASTER_PASSWORD is not set and convenience unlock is unavailable")
	}
	if unlockErr == nil && handle != nil {
		setAuditHMACKey(handle.AuditHMACKey())
	}
	return handle, unlockErr
}
