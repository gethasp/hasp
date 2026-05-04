//go:build darwin || linux

package runner

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
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

func TestRunnerExecute_TTY_CoverageBranches(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("PTY allocation only supported on darwin/linux; got %s", runtime.GOOS)
	}

	if _, err := Execute(context.Background(), Input{Command: []string{"/definitely/missing"}, TTY: true}); err == nil {
		t.Fatal("expected pty start error")
	}

	res, err := Execute(context.Background(), Input{
		Command: []string{"/bin/sh", "-c", "printf fallback"},
		TTY:     true,
	})
	if err != nil {
		t.Fatalf("tty fallback stdout: %v", err)
	}
	if !strings.Contains(string(res.Stdout), "fallback") {
		t.Fatalf("fallback stdout = %q", res.Stdout)
	}

	var stdinStdout bytes.Buffer
	res, err = Execute(context.Background(), Input{
		Command: []string{"/bin/sh", "-c", "read line; printf %s \"$line\""},
		Stdin:   strings.NewReader("typed\n"),
		Stdout:  &stdinStdout,
		TTY:     true,
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("tty stdin err=%v exit=%d stdout=%q", err, res.ExitCode, stdinStdout.String())
	}
	if !strings.Contains(stdinStdout.String(), "typed") {
		t.Fatalf("tty stdin stdout = %q", stdinStdout.String())
	}

	res, err = Execute(context.Background(), Input{
		Command: []string{"/bin/sh", "-c", "exit 7"},
		TTY:     true,
	})
	if err != nil {
		t.Fatalf("tty exit command: %v", err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("tty exit code = %d", res.ExitCode)
	}

	lockRunnerSeams(t)
	origAfter := ptyAfter
	origWait := ptyWaitCommand
	t.Cleanup(func() {
		ptyAfter = origAfter
		ptyWaitCommand = origWait
	})
	ptyAfter = func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}
	if _, err := Execute(context.Background(), Input{
		Command: []string{"/bin/sh", "-c", "sleep 0.05"},
		TTY:     true,
	}); err != nil {
		t.Fatalf("forced pty drain timeout: %v", err)
	}
	ptyAfter = origAfter

	ptyWaitCommand = func(cmd *exec.Cmd) error {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return errors.New("wait")
	}
	if _, err := Execute(context.Background(), Input{
		Command: []string{"/bin/sh", "-c", "sleep 1"},
		TTY:     true,
	}); err == nil || !strings.Contains(err.Error(), "wait") {
		t.Fatalf("expected pty wait error, got %v", err)
	}
	ptyWaitCommand = origWait
}
