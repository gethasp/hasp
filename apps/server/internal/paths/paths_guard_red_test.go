package paths

import (
	"os"
	"strings"
	"testing"
)

// TestResolveGuardRefusesRealHomeInTestContext verifies the hard guard that
// prevents test runs from falling back to the real user home directory.
// This test runs inside a go test binary, so testing.Testing() is always
// true here; we rely on that rather than HASP_TEST.

func TestResolveGuardRefusesRealHomeInTestContext(t *testing.T) {
	orig := configReadFileFn
	defer func() { configReadFileFn = orig }()
	// Make LoadConfig return no home dir so we reach the fallback paths.
	configReadFileFn = func(string) ([]byte, error) { return nil, os.ErrNotExist }

	// Case a: testing.Testing() == true, HASP_HOME not set → must error
	t.Setenv(EnvHome, "")
	_, err := Resolve()
	if err == nil {
		t.Fatal("expected error when HASP_HOME is unset under go test, got nil")
	}
	if !strings.Contains(err.Error(), "HASP_HOME") || !strings.Contains(err.Error(), "set explicitly") {
		t.Fatalf("error message missing required hints, got: %v", err)
	}
}

func TestResolveGuardAllowsExplicitHaspHome(t *testing.T) {
	orig := configReadFileFn
	defer func() { configReadFileFn = orig }()
	configReadFileFn = func(string) ([]byte, error) { return nil, os.ErrNotExist }

	// Case b: HASP_HOME set to a temp dir → must succeed and return that dir
	home := t.TempDir()
	t.Setenv(EnvHome, home)
	resolved, err := Resolve()
	if err != nil {
		t.Fatalf("expected success when HASP_HOME is set, got: %v", err)
	}
	if resolved.HomeDir != home {
		t.Fatalf("HomeDir = %q, want %q", resolved.HomeDir, home)
	}
}

func TestResolveGuardRefusesWithHaspTestEnvVar(t *testing.T) {
	orig := configReadFileFn
	defer func() { configReadFileFn = orig }()
	configReadFileFn = func(string) ([]byte, error) { return nil, os.ErrNotExist }

	// Case c: HASP_TEST=1, HASP_HOME not set → must error
	t.Setenv("HASP_TEST", "1")
	t.Setenv(EnvHome, "")
	_, err := Resolve()
	if err == nil {
		t.Fatal("expected error when HASP_TEST=1 and HASP_HOME unset, got nil")
	}
	if !strings.Contains(err.Error(), "HASP_HOME") || !strings.Contains(err.Error(), "set explicitly") {
		t.Fatalf("error message missing required hints, got: %v", err)
	}
}
