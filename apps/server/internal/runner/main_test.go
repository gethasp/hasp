package runner

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// The paths package refuses real-$HOME fallback under testing.Testing()
	// or HASP_TEST=1; default HASP_HOME to a per-process tmp dir so runner
	// tests never touch the user's real ~/.hasp directory and the guard does
	// not fire on go test runs.
	dir, err := os.MkdirTemp("", "hasp-test-runner-*")
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
