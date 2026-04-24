package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveUsesExplicitEnvOverrides(t *testing.T) {
	base := t.TempDir()
	origUserConfigDir := userConfigDir
	origUserHomeDir := userHomeDir
	origPathStat := pathStat
	origRead := configReadFileFn
	defer func() {
		userConfigDir = origUserConfigDir
		userHomeDir = origUserHomeDir
		pathStat = origPathStat
		configReadFileFn = origRead
	}()
	userConfigDir = func() (string, error) { return base, nil }
	userHomeDir = func() (string, error) { return base, nil }
	pathStat = os.Stat
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
	origUserHomeDir := userHomeDir
	origPathStat := pathStat
	origRead := configReadFileFn
	defer func() {
		userConfigDir = origUserConfigDir
		userHomeDir = origUserHomeDir
		pathStat = origPathStat
		configReadFileFn = origRead
	}()
	userConfigDir = func() (string, error) { return base, nil }
	userHomeDir = func() (string, error) { return t.TempDir(), nil }
	pathStat = os.Stat
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
	origUserHomeDir := userHomeDir
	origPathStat := pathStat
	origRead := configReadFileFn
	defer func() {
		userConfigDir = origUserConfigDir
		userHomeDir = origUserHomeDir
		pathStat = origPathStat
		configReadFileFn = origRead
	}()
	userConfigDir = func() (string, error) { return base, nil }
	userHomeDir = func() (string, error) { return t.TempDir(), nil }
	pathStat = os.Stat
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
	origUserHomeDir := userHomeDir
	origPathStat := pathStat
	origRead := configReadFileFn
	defer func() {
		userConfigDir = origUserConfigDir
		userHomeDir = origUserHomeDir
		pathStat = origPathStat
		configReadFileFn = origRead
	}()

	userConfigDir = func() (string, error) { return base, nil }
	userHomeDir = func() (string, error) { return t.TempDir(), nil }
	pathStat = os.Stat
	configReadFileFn = func(string) ([]byte, error) { return nil, fmt.Errorf("read fail") }
	t.Setenv(EnvHome, "")
	t.Setenv(EnvSocket, "")
	if _, err := Resolve(); err == nil {
		t.Fatal("expected config load failure")
	}
}

func TestResolvePrefersExistingLegacyDotHaspVault(t *testing.T) {
	base := t.TempDir()
	home := t.TempDir()
	legacyHome := filepath.Join(home, ".hasp")
	if err := os.MkdirAll(legacyHome, 0o700); err != nil {
		t.Fatalf("mkdir legacy home: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyHome, "vault.json.enc"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write legacy vault: %v", err)
	}

	origUserConfigDir := userConfigDir
	origUserHomeDir := userHomeDir
	origPathStat := pathStat
	origRead := configReadFileFn
	defer func() {
		userConfigDir = origUserConfigDir
		userHomeDir = origUserHomeDir
		pathStat = origPathStat
		configReadFileFn = origRead
	}()

	userConfigDir = func() (string, error) { return base, nil }
	userHomeDir = func() (string, error) { return home, nil }
	pathStat = os.Stat
	configReadFileFn = os.ReadFile
	t.Setenv(EnvHome, "")
	t.Setenv(EnvSocket, "")

	resolved, err := Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	if resolved.HomeDir != legacyHome {
		t.Fatalf("home dir = %q, want %q", resolved.HomeDir, legacyHome)
	}
}

func TestResolvePropagatesLegacyHomeResolutionFailure(t *testing.T) {
	base := t.TempDir()
	origUserConfigDir := userConfigDir
	origUserHomeDir := userHomeDir
	origPathStat := pathStat
	origRead := configReadFileFn
	defer func() {
		userConfigDir = origUserConfigDir
		userHomeDir = origUserHomeDir
		pathStat = origPathStat
		configReadFileFn = origRead
	}()

	userConfigDir = func() (string, error) { return base, nil }
	userHomeDir = func() (string, error) { return t.TempDir(), nil }
	pathStat = func(string) (os.FileInfo, error) { return nil, fmt.Errorf("stat fail") }
	configReadFileFn = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	t.Setenv(EnvHome, "")
	t.Setenv(EnvSocket, "")

	if _, err := Resolve(); err == nil || !strings.Contains(err.Error(), "resolve legacy home: stat fail") {
		t.Fatalf("expected legacy home failure, got %v", err)
	}
}

func TestExistingLegacyHomeErrorBranches(t *testing.T) {
	origUserHomeDir := userHomeDir
	origPathStat := pathStat
	defer func() {
		userHomeDir = origUserHomeDir
		pathStat = origPathStat
	}()

	userHomeDir = func() (string, error) { return "", fmt.Errorf("home fail") }
	if _, err := existingLegacyHome(); err == nil || !strings.Contains(err.Error(), "home fail") {
		t.Fatalf("expected userHomeDir failure, got %v", err)
	}

	userHomeDir = func() (string, error) { return t.TempDir(), nil }
	pathStat = func(string) (os.FileInfo, error) { return nil, fmt.Errorf("stat fail") }
	if _, err := existingLegacyHome(); err == nil || !strings.Contains(err.Error(), "stat fail") {
		t.Fatalf("expected pathStat failure, got %v", err)
	}
}
