package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// The paths package refuses real-$HOME fallback under testing.Testing()
	// or HASP_TEST=1; default HASP_HOME to a per-process tmp dir so cmd/hasp
	// tests never touch the user's real ~/.hasp directory and the guard does
	// not fire on go test runs.
	dir, err := os.MkdirTemp("", "hasp-test-cmd-*")
	if err == nil {
		os.Setenv("HASP_HOME", dir)
	}
	os.Setenv("HASP_TEST", "1")
	code := m.Run()
	if dir != "" {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}

func TestRunSuccessPath(t *testing.T) {
	var stdout bytes.Buffer
	code := run(context.Background(), []string{"help"}, bytes.NewBuffer(nil), &stdout, &stdout)
	if code != 0 {
		t.Fatalf("run returned code %d", code)
	}
	if stdout.Len() == 0 {
		t.Fatal("expected help output")
	}
}

func TestRunFailurePath(t *testing.T) {
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"does-not-exist"}, bytes.NewBuffer(nil), &stderr, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if stderr.Len() == 0 {
		t.Fatal("expected error output")
	}
}

func TestRunUnknownCommandReturnsUserInputExitCode(t *testing.T) {
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"does-not-exist"}, bytes.NewBuffer(nil), &stderr, &stderr)
	if code != 2 {
		t.Fatalf("unknown command exit code = %d, want 2 (user input)", code)
	}
}

func TestRunFailureEmitsStructuredJSONOnStderrInJSONMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--json", "does-not-exist"}, bytes.NewBuffer(nil), &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit code for unknown command")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should stay empty in --json error path, got %q", stdout.String())
	}
	got := strings.TrimSpace(stderr.String())
	var decoded map[string]map[string]string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("expected JSON envelope on stderr, got %q (decode err %v)", got, err)
	}
	inner, ok := decoded["error"]
	if !ok {
		t.Fatalf("missing 'error' key in envelope: %s", got)
	}
	if !strings.Contains(inner["message"], "unknown command") {
		t.Fatalf("message = %q, want it to mention 'unknown command'", inner["message"])
	}
	if inner["code"] != "E_USER_INPUT" {
		t.Fatalf("code = %q, want E_USER_INPUT", inner["code"])
	}
}

func TestMainUsesExitFn(t *testing.T) {
	origArgs := os.Args
	origExit := exitFn
	defer func() {
		os.Args = origArgs
		exitFn = origExit
	}()

	var code int
	exitFn = func(v int) { code = v }
	os.Args = []string{"hasp", "help"}
	main()
	if code != 0 {
		t.Fatalf("main exit code = %d, want 0", code)
	}
}

func TestProcessExists(t *testing.T) {
	if !processExists(os.Getpid()) {
		t.Fatal("current process should exist")
	}
	if processExists(999999) {
		t.Fatal("sentinel process should not exist")
	}
}

func TestContextWithTestDaemonParentIgnoresInvalidEnv(t *testing.T) {
	t.Setenv(testDaemonParentPIDEnv, "not-a-pid")

	ctx, cancel := contextWithTestDaemonParent(context.Background())
	select {
	case <-ctx.Done():
		t.Fatal("invalid parent pid should not cancel context")
	default:
	}
	cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("cancel did not close context")
	}
}

func TestContextWithTestDaemonParentCancelsWhenParentGone(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start parent sentinel: %v", err)
	}
	parentPID := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait parent sentinel: %v", err)
	}
	t.Setenv(testDaemonParentPIDEnv, strconv.Itoa(parentPID))

	ctx, cancel := contextWithTestDaemonParent(context.Background())
	defer cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("parent-gone context did not cancel")
	}
}

func TestContextWithTestDaemonParentStopsOnManualCancel(t *testing.T) {
	t.Setenv(testDaemonParentPIDEnv, strconv.Itoa(os.Getpid()))

	ctx, cancel := contextWithTestDaemonParent(context.Background())
	cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("manual cancel did not close context")
	}
}
