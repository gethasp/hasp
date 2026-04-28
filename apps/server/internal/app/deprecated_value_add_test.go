package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// hasp-n0ce: 'hasp set' and 'hasp capture' are aliases-for-one-release pending
// removal. Both must continue to work but emit a stderr deprecation pointing
// to the unified 'hasp secret add' surface.

func TestSetEmitsDeprecationWarning(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	var stderr bytes.Buffer
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, &stderr); err != nil {
		t.Fatalf("set: %v", err)
	}
	got := stderr.String()
	if !strings.Contains(got, "deprecated") {
		t.Fatalf("expected deprecation in stderr, got %q", got)
	}
	if !strings.Contains(got, "secret add") {
		t.Fatalf("expected stderr to point at 'secret add', got %q", got)
	}
}

func TestCaptureEmitsDeprecationWarning(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	starter := newDaemonTestStarter(t)
	var stderr bytes.Buffer
	args := []string{
		"capture",
		"--name", "API_TOKEN",
		"--value", "abc123",
		"--project-root", projectRoot,
		"--grant-project", "window",
		"--grant-window", "15m",
		"--grant-write",
	}
	if err := runWithStarter(context.Background(), args, bytes.NewBuffer(nil), io.Discard, &stderr, starter); err != nil {
		t.Fatalf("capture: %v stderr=%q", err, stderr.String())
	}
	got := stderr.String()
	if !strings.Contains(got, "deprecated") {
		t.Fatalf("expected deprecation in stderr, got %q", got)
	}
	if !strings.Contains(got, "secret add") {
		t.Fatalf("expected stderr to point at 'secret add', got %q", got)
	}
}
