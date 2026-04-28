package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
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

func TestRunUnknownCommandReturnsExitCodeOne(t *testing.T) {
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"does-not-exist"}, bytes.NewBuffer(nil), &stderr, &stderr)
	if code != 1 {
		t.Fatalf("unknown command exit code = %d, want 1 (generic)", code)
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
