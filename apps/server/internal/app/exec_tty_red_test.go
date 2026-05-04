package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// hasp-ymuy: when the caller's stdout is interactive, executeCommand must
// (a) tell the runner to allocate a PTY (Input.TTY=true) and (b) wrap
// Stdout in the ANSI-aware streaming redactor so secrets split by colour
// escapes still redact.

func TestExecStreaming_TTYMode_RequestsPTYAndRedactsAcrossANSI(t *testing.T) {
	prev := stdoutIsTTYFn
	stdoutIsTTYFn = func(io.Writer) bool { return true }
	t.Cleanup(func() { stdoutIsTTYFn = prev })

	secret := []byte("AKIATEST123")
	var captured bytes.Buffer
	runnerFn := func(ctx context.Context, in runner.Input) (runner.Result, error) {
		if !in.TTY {
			t.Fatalf("expected runner.Input.TTY=true when stdoutIsTTYFn reports a TTY; got false")
		}
		_, _ = in.Stdout.Write([]byte("payload AKIA\x1b[1mTEST\x1b[0m123 trailing"))
		return runner.Result{ExitCode: 0}, nil
	}
	if err := runStreamingExecTTY(context.Background(), &captured, []store.Item{{Name: "k", Value: secret}}, runnerFn); err != nil {
		t.Fatalf("run: %v", err)
	}
	if bytes.Contains(captured.Bytes(), secret) {
		t.Fatalf("ANSI-aware writer leaked secret across colour escape; out=%q", captured.Bytes())
	}
	if !strings.Contains(captured.String(), "payload ") {
		t.Fatalf("non-secret bytes dropped from output; out=%q", captured.Bytes())
	}
}

func TestExecStreaming_NonTTYMode_LeavesTTYFalseAndUsesPlainRedactor(t *testing.T) {
	prev := stdoutIsTTYFn
	stdoutIsTTYFn = func(io.Writer) bool { return false }
	t.Cleanup(func() { stdoutIsTTYFn = prev })

	secret := []byte("hunter2pass")
	var captured bytes.Buffer
	runnerFn := func(ctx context.Context, in runner.Input) (runner.Result, error) {
		if in.TTY {
			t.Fatalf("expected runner.Input.TTY=false when caller is not a TTY; got true")
		}
		_, _ = in.Stdout.Write([]byte("plain hunter2pass output"))
		return runner.Result{ExitCode: 0}, nil
	}
	if err := runStreamingExecTTY(context.Background(), &captured, []store.Item{{Name: "p", Value: secret}}, runnerFn); err != nil {
		t.Fatalf("run: %v", err)
	}
	if bytes.Contains(captured.Bytes(), secret) {
		t.Fatalf("non-TTY path failed to redact plain literal; out=%q", captured.Bytes())
	}
}

// runStreamingExecTTY mirrors runStreamingExec but threads through the
// stdoutIsTTYFn seam the same way executeCommand does. The harness is
// intentionally tiny so it can exercise the TTY-vs-non-TTY branch without
// pulling in the daemon or the broker.
func runStreamingExecTTY(ctx context.Context, dst io.Writer, items []store.Item,
	runnerFn func(context.Context, runner.Input) (runner.Result, error)) error {

	tty := stdoutIsTTYFn(dst)
	var swOut *redactor.StreamingWriter
	if tty {
		swOut = redactor.NewStreamingWriterANSIAware(dst, items)
	} else {
		swOut = redactor.NewStreamingWriter(dst, items)
	}

	result, err := runnerFn(ctx, runner.Input{
		Command: []string{"fake"},
		Stdout:  swOut,
		TTY:     tty,
	})
	_ = swOut.Flush()
	_ = result
	return err
}
