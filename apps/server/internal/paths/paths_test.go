package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveUsesExplicitEnvOverrides(t *testing.T) {
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
	t.Setenv(EnvHome, "")
	t.Setenv(EnvSocket, "")
	resolved, err := Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("user config dir: %v", err)
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

	orig := userConfigDir
	defer func() { userConfigDir = orig }()
	userConfigDir = func() (string, error) { return "", fmt.Errorf("config fail") }
	t.Setenv(EnvSocket, "")
	if _, err := Resolve(); err == nil {
		t.Fatal("expected user config dir failure")
	}
}
