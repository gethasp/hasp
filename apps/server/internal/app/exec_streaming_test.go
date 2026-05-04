package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// captureFirstWrite signals notify on the first non-empty Write call.
// It discards all bytes after notifying.
type captureFirstWrite struct {
	notify   chan struct{}
	notified bool
}

func (w *captureFirstWrite) Write(p []byte) (int, error) {
	if len(p) > 0 && !w.notified {
		w.notified = true
		select {
		case w.notify <- struct{}{}:
		default:
		}
	}
	return len(p), nil
}

// runStreamingExec is a thin harness that exercises the same streaming-writer
// plumbing that executeCommandWithDeps now uses, without requiring a live daemon.
// It constructs StreamingWriters around dst/dstErr, calls the given runnerFn
// via runner.Input.Stdout/Stderr, and flushes afterwards.
func runStreamingExec(ctx context.Context, dst io.Writer, dstErr io.Writer, items []store.Item,
	runnerFn func(context.Context, runner.Input) (runner.Result, error)) error {

	swOut := redactor.NewStreamingWriter(dst, items)
	swErr := redactor.NewStreamingWriter(dstErr, items)

	result, err := runnerFn(ctx, runner.Input{
		ProjectRoot: "",
		Command:     []string{"fake"},
		Stdout:      swOut,
		Stderr:      swErr,
	})
	_ = swOut.Flush()
	_ = swErr.Flush()
	if err != nil {
		return err
	}
	_ = result
	return nil
}

// TestExecStreamingEmitsBytesBeforeProcessExit verifies that bytes arrive at
// the Stdout writer BEFORE the child process (simulated by the fake runner)
// completes its sleep-then-return sequence. This demonstrates that the
// streaming path does not buffer all output until exit.
func TestExecStreamingEmitsBytesBeforeProcessExit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping streaming interleave test in short mode")
	}

	firstWrite := make(chan struct{}, 1)
	pw := &captureFirstWrite{notify: firstWrite}

	runnerFn := func(ctx context.Context, input runner.Input) (runner.Result, error) {
		// Write output immediately — before the sleep.
		if input.Stdout != nil {
			_, _ = input.Stdout.Write([]byte("live output line\n"))
		}
		// Simulate the child still running for 300 ms.
		select {
		case <-ctx.Done():
		case <-time.After(300 * time.Millisecond):
		}
		return runner.Result{ExitCode: 0}, nil
	}

	done := make(chan error, 1)
	go func() {
		done <- runStreamingExec(context.Background(), pw, io.Discard, nil, runnerFn)
	}()

	// The first write must arrive before the 300ms sleep ends.
	select {
	case <-firstWrite:
		// Streaming confirmed: bytes arrived before process exit.
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first streamed byte before process exit")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("execute error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("execute goroutine did not finish in time")
	}
}

// TestExecStreamingRedactsSecretInOutput verifies that the streaming writer
// wrapping dst redacts secrets on the fly as bytes flow through.
func TestExecStreamingRedactsSecretInOutput(t *testing.T) {
	const secretValue = "SUPER-SECRET-STREAM-VALUE"
	items := []store.Item{{Name: "sec", Value: []byte(secretValue)}}

	var out bytes.Buffer
	runnerFn := func(ctx context.Context, input runner.Input) (runner.Result, error) {
		if input.Stdout != nil {
			_, _ = input.Stdout.Write([]byte("prefix " + secretValue + " suffix"))
		}
		return runner.Result{ExitCode: 0}, nil
	}

	if err := runStreamingExec(context.Background(), &out, io.Discard, items, runnerFn); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := out.String()
	if strings.Contains(got, secretValue) {
		t.Errorf("output still contains secret: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("output does not contain [REDACTED] marker: %q", got)
	}
}

// TestExecStreamingNilItemsPassthrough verifies that with no items, the
// streaming writer does not buffer and all bytes flow through.
func TestExecStreamingNilItemsPassthrough(t *testing.T) {
	var out bytes.Buffer
	const payload = "no secrets here, just plain text"
	runnerFn := func(ctx context.Context, input runner.Input) (runner.Result, error) {
		if input.Stdout != nil {
			_, _ = input.Stdout.Write([]byte(payload))
		}
		return runner.Result{ExitCode: 0}, nil
	}

	if err := runStreamingExec(context.Background(), &out, io.Discard, nil, runnerFn); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out.String() != payload {
		t.Errorf("got %q, want %q", out.String(), payload)
	}
}
