//go:build darwin || linux

package runner

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"
)

// hasp-ymuy: when Input.TTY is true the runner must allocate a PTY pair so
// the child detects an interactive terminal. With no PTY allocated the child
// sees a non-tty stdout and many tools (colour, progress bars, sudo password
// prompts, vim) misbehave. The fix wires creack/pty into runner.Execute,
// pipes pty.master ↔ Input.Stdin/Stdout, and falls back to the existing
// non-TTY path when Input.TTY is false.

func TestRunnerExecute_TTY_ChildSeesTerminal(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("PTY allocation only supported on darwin/linux; got %s", runtime.GOOS)
	}
	var stdout bytes.Buffer
	res, err := Execute(context.Background(), Input{
		Command: []string{"/bin/sh", "-c", "[ -t 1 ] && echo have-tty || echo no-tty"},
		Stdout:  &stdout,
		TTY:     true,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d; stdout=%q", res.ExitCode, stdout.String())
	}
	if !strings.Contains(stdout.String(), "have-tty") {
		t.Fatalf("child did not detect tty; stdout=%q", stdout.String())
	}
}

func TestRunnerExecute_TTY_OffStaysNonTerminal(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("PTY allocation only supported on darwin/linux; got %s", runtime.GOOS)
	}
	var stdout bytes.Buffer
	res, err := Execute(context.Background(), Input{
		Command: []string{"/bin/sh", "-c", "[ -t 1 ] && echo have-tty || echo no-tty"},
		Stdout:  &stdout,
		// TTY left at zero value (false)
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d; stdout=%q", res.ExitCode, stdout.String())
	}
	if !strings.Contains(stdout.String(), "no-tty") {
		t.Fatalf("non-TTY mode unexpectedly produced a tty for the child; stdout=%q", stdout.String())
	}
}

func TestRunnerExecute_TTY_StdoutBytesReachCaller(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("PTY allocation only supported on darwin/linux; got %s", runtime.GOOS)
	}
	var stdout bytes.Buffer
	res, err := Execute(context.Background(), Input{
		Command: []string{"/bin/sh", "-c", "printf hello-pty"},
		Stdout:  &stdout,
		TTY:     true,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d", res.ExitCode)
	}
	if !strings.Contains(stdout.String(), "hello-pty") {
		t.Fatalf("expected stdout to contain hello-pty; got %q", stdout.String())
	}
}
