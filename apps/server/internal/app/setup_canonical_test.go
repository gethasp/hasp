package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// hasp-v88h: hasp setup is the canonical setup surface. hasp init,
// hasp bootstrap, and hasp project bind continue to work but each emits
// a single stderr line pointing at hasp setup so docs and quickstarts
// can converge on one verb.

func TestInitEmitsSetupRedirectOnStderr(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	var stderr bytes.Buffer
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, &stderr); err != nil {
		t.Fatalf("init: %v", err)
	}
	got := stderr.String()
	if !strings.Contains(got, "hasp setup") {
		t.Fatalf("expected init stderr to point at 'hasp setup', got %q", got)
	}
}

func TestProjectBindEmitsSetupRedirectOnStderr(t *testing.T) {
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
	var stderr bytes.Buffer
	// project bind may fail later for unrelated reasons (we don't really
	// care for this test); only the redirect line matters.
	_ = Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard, &stderr)
	got := stderr.String()
	if !strings.Contains(got, "hasp setup") {
		t.Fatalf("expected project bind stderr to point at 'hasp setup', got %q", got)
	}
}

// hasp-th45: bootstrap is a first-class flow; the setup advisory must NOT fire.
func TestBootstrapDoesNotEmitSetupRedirectOnStderr(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	var stderr bytes.Buffer
	_ = Run(context.Background(), []string{"bootstrap", "profiles"}, bytes.NewBuffer(nil), io.Discard, &stderr)
	got := stderr.String()
	if strings.Contains(got, "hasp setup") {
		t.Fatalf("bootstrap must not emit the setup advisory, got stderr: %q", got)
	}
}
