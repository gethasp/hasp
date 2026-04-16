package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveUsesExplicitEnvOverrides(t *testing.T) {
	base := t.TempDir()
	origUserConfigDir := userConfigDir
	origRead := configReadFileFn
	defer func() {
		userConfigDir = origUserConfigDir
		configReadFileFn = origRead
	}()
	userConfigDir = func() (string, error) { return base, nil }
	configReadFileFn = os.ReadFile

	home := t.TempDir()
	socket := filepath.Join(t.TempDir(), "daemon.sock")
	t.Setenv(EnvHome, home)
	t.Setenv(EnvSocket, socket)

	resolved, err := Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	if resolved.HomeDir != home {
		t.Fatalf("home dir = %q, want %q", resolved.HomeDir, home)
	}
	if resolved.SocketPath != socket {
		t.Fatalf("socket path = %q, want %q", resolved.SocketPath, socket)
	}
	if resolved.StatePath != filepath.Join(home, "vault.json.enc") {
		t.Fatalf("unexpected state path: %q", resolved.StatePath)
	}
}

func TestResolveUsesUserConfigDirFallback(t *testing.T) {
	base := t.TempDir()
	origUserConfigDir := userConfigDir
	origRead := configReadFileFn
	defer func() {
		userConfigDir = origUserConfigDir
		configReadFileFn = origRead
	}()
	userConfigDir = func() (string, error) { return base, nil }
	configReadFileFn = os.ReadFile

	t.Setenv(EnvHome, "")
	t.Setenv(EnvSocket, "")
	resolved, err := Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	expectedHome := filepath.Join(base, "hasp")
	if resolved.HomeDir != expectedHome {
		t.Fatalf("home dir = %q, want %q", resolved.HomeDir, expectedHome)
	}
	if resolved.SocketPath != filepath.Join(expectedHome, "runtime", "daemon.sock") {
		t.Fatalf("unexpected socket path: %q", resolved.SocketPath)
	}
}

func TestResolveUsesFallbackHomeWithExplicitSocketAndPropagatesConfigDirFailure(t *testing.T) {
	base := t.TempDir()
	origUserConfigDir := userConfigDir
	origRead := configReadFileFn
	defer func() {
		userConfigDir = origUserConfigDir
		configReadFileFn = origRead
	}()
	userConfigDir = func() (string, error) { return base, nil }
	configReadFileFn = os.ReadFile

	t.Setenv(EnvHome, "")
	customSocket := filepath.Join(t.TempDir(), "daemon.sock")
	t.Setenv(EnvSocket, customSocket)
	resolved, err := Resolve()
	if err != nil {
		t.Fatalf("resolve with explicit socket: %v", err)
	}
	if resolved.SocketPath != customSocket {
		t.Fatalf("socket path = %q, want %q", resolved.SocketPath, customSocket)
	}

	callCount := 0
	userConfigDir = func() (string, error) {
		callCount++
		if callCount == 1 {
			return base, nil
		}
		return "", fmt.Errorf("config fail")
	}
	configReadFileFn = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	t.Setenv(EnvSocket, "")
	if _, err := Resolve(); err == nil {
		t.Fatal("expected user config dir failure")
	}
}

func TestResolvePropagatesConfigLoadFailure(t *testing.T) {
	base := t.TempDir()
	origUserConfigDir := userConfigDir
	origRead := configReadFileFn
	defer func() {
		userConfigDir = origUserConfigDir
		configReadFileFn = origRead
	}()

	userConfigDir = func() (string, error) { return base, nil }
	configReadFileFn = func(string) ([]byte, error) { return nil, fmt.Errorf("read fail") }
	t.Setenv(EnvHome, "")
	t.Setenv(EnvSocket, "")
	if _, err := Resolve(); err == nil {
		t.Fatal("expected config load failure")
	}
}
