package runtimeops

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// globalJSON reports whether the global --json flag is active, falling back to
// false when deps.GlobalJSON is not wired (e.g. in contract tests).
func globalJSON(ctx context.Context, deps Deps) bool {
	if deps.GlobalJSON != nil {
		return deps.GlobalJSON(ctx)
	}
	return false
}

// renderBackupResultFn calls deps.RenderBackupResult when wired, or falls back
// to a minimal tabwriter implementation.
func renderBackupResultFn(deps Deps, out io.Writer, title string, lead string, path string, checkpoint store.AuditCheckpoint) error {
	if deps.RenderBackupResult != nil {
		return deps.RenderBackupResult(out, title, lead, path, checkpoint)
	}
	// Minimal fallback so contract tests don't panic.
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\n", title, lead)
	fmt.Fprintf(tw, "path\t%s\n", path)
	fmt.Fprintf(tw, "sequence\t%d\n", checkpoint.Sequence)
	fmt.Fprintf(tw, "hash\t%s\n", checkpoint.Hash)
	return tw.Flush()
}

// renderStatusHumanFallback is a self-contained status renderer used when
// deps.RenderStatusHuman is not wired.
func renderStatusHumanFallback(stdout io.Writer, reply runtime.StatusResponse, termColsFn func() int) error {
	cols := 0
	if termColsFn != nil {
		cols = termColsFn()
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	const socketKey = "socket"
	socketPath := clipForTerminal(reply.SocketPath, len(socketKey)+2, cols)
	fmt.Fprintf(tw, "%s\t%s\n", socketKey, socketPath)
	fmt.Fprintf(tw, "pid\t%d\n", reply.PID)
	fmt.Fprintf(tw, "started_at\t%s\n", reply.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(tw, "active_sessions\t%d\n", reply.ActiveSessions)
	fmt.Fprintf(tw, "audit_degraded\t%t\n", reply.AuditDegraded)
	if reply.AuditDegradedAt != nil {
		fmt.Fprintf(tw, "audit_degraded_at\t%s\n", reply.AuditDegradedAt.Format(time.RFC3339))
	}
	return tw.Flush()
}

// clipForTerminal returns value, possibly leading-ellipsis-clipped, so that
// `prefixLen + len(result)` fits in `columns`. If columns <= 0 (unknown
// terminal width) or the value already fits, value is returned as-is.
func clipForTerminal(value string, prefixLen, columns int) string {
	if columns <= 0 {
		return value
	}
	if prefixLen+len(value) <= columns {
		return value
	}
	budget := columns - prefixLen - 1
	if budget <= 0 {
		return value
	}
	return "…" + value[len(value)-budget:]
}

// connectIfRunningFn calls deps.ConnectIfRunning when wired, or falls back to
// a direct connect attempt.
func connectIfRunningFn(ctx context.Context, deps Deps, s Starter) *runtime.Client {
	if deps.ConnectIfRunning != nil {
		return deps.ConnectIfRunning(ctx, s)
	}
	// Fallback: attempt connect without starting.
	if s == nil {
		return nil
	}
	client, err := s.Connect(ctx)
	if err != nil {
		return nil
	}
	return client
}

// renderNotRunningFn calls deps.RenderNotRunning when wired, or writes the
// canonical "not running" text/JSON.
func renderNotRunningFn(deps Deps, stdout io.Writer, jsonOutput bool) error {
	if deps.RenderNotRunning != nil {
		return deps.RenderNotRunning(stdout, jsonOutput)
	}
	if jsonOutput {
		if deps.WriteJSONResponse != nil {
			return deps.WriteJSONResponse(stdout, map[string]any{"running": false})
		}
		_, err := fmt.Fprintf(stdout, `{"running":false}`+"\n")
		return err
	}
	_, err := fmt.Fprintln(stdout, "not running")
	return err
}
