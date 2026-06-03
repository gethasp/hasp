//go:build darwin

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnsupportedKeyringReturnsUnavailable(t *testing.T) {
	var keyring unsupportedKeyring
	if err := keyring.Set(context.Background(), "svc", "acct", "value"); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected unavailable from Set, got %v", err)
	}
	if _, err := keyring.Get("svc", "acct"); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected unavailable from Get, got %v", err)
	}
	if err := keyring.Delete("svc", "acct"); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected unavailable from Delete, got %v", err)
	}
}

func TestDarwinKeyringSetUsesNativeSetterWhenAvailable(t *testing.T) {
	origNative := nativeKeychainSet
	t.Cleanup(func() { nativeKeychainSet = origNative })

	called := false
	nativeKeychainSet = func(service, account, value string) error {
		called = true
		if service != "svc" || account != "acct" || value != "value" {
			t.Fatalf("native setter args = %q %q %q", service, account, value)
		}
		return nil
	}
	if err := (DarwinKeyring{}).Set(context.Background(), "svc", "acct", "value"); err != nil {
		t.Fatalf("native set: %v", err)
	}
	if !called {
		t.Fatal("native setter was not called")
	}

	nativeKeychainSet = func(string, string, string) error { return errors.New("native fail") }
	if err := (DarwinKeyring{}).Set(context.Background(), "svc", "acct", "value"); err == nil || !strings.Contains(err.Error(), "native fail") {
		t.Fatalf("expected native failure, got %v", err)
	}
}

func TestDarwinKeyringCommands(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "security.log")
	scriptPath := filepath.Join(tmpDir, "security")
	keychainPath := filepath.Join(tmpDir, "login.keychain-db")
	if err := os.WriteFile(keychainPath, []byte("fake"), 0o600); err != nil {
		t.Fatalf("write fake keychain: %v", err)
	}
	if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" >> \""+logPath+"\"\ncase \"$1\" in\ndefault-keychain) printf '\""+keychainPath+"\"\\n' ;;\nfind-generic-password) printf 'stored-value\\n' ;;\nesac\n"), 0o755); err != nil {
		t.Fatalf("write fake security: %v", err)
	}
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", tmpDir+":"+origPath)
	t.Setenv("HASP_TEST_SECURITY_BIN", scriptPath)

	keyring := DarwinKeyring{}
	if err := keyring.Set(context.Background(), "svc", "acct", "value"); err != nil {
		t.Fatalf("set keyring: %v", err)
	}
	value, err := keyring.Get("svc", "acct")
	if err != nil {
		t.Fatalf("get keyring: %v", err)
	}
	if value != "stored-value" {
		t.Fatalf("value = %q", value)
	}
	if err := keyring.Delete("svc", "acct"); err != nil {
		t.Fatalf("delete keyring: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	if !strings.Contains(string(data), "default-keychain") || !strings.Contains(string(data), "add-generic-password") || !strings.Contains(string(data), "find-generic-password") || !strings.Contains(string(data), "delete-generic-password") {
		t.Fatalf("unexpected command log: %s", string(data))
	}
	if !strings.Contains(string(data), keychainPath) {
		t.Fatalf("expected explicit keychain path in command log, got %s", string(data))
	}
	if _, ok := NewDefaultKeyring().(DarwinKeyring); !ok {
		t.Fatal("expected darwin default keyring")
	}
}

func TestDarwinKeyringSetSkipsWhenDefaultKeychainMissing(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "security.log")
	scriptPath := filepath.Join(tmpDir, "security")
	if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" >> \""+logPath+"\"\nif [[ \"$1\" == \"default-keychain\" ]]; then\n  echo 'security: SecKeychainCopyDefault: A default keychain could not be found.' >&2\n  exit 1\nfi\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake security: %v", err)
	}
	t.Setenv("HASP_TEST_SECURITY_BIN", scriptPath)

	keyring := DarwinKeyring{}
	if err := keyring.Set(context.Background(), "svc", "acct", "value"); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected keyring unavailable, got %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	if strings.Contains(string(data), "add-generic-password") {
		t.Fatalf("expected add-generic-password to be skipped, got %s", string(data))
	}
}

func TestDarwinKeyringErrorPaths(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "security")
	keychainPath := filepath.Join(tmpDir, "login.keychain-db")
	if err := os.WriteFile(keychainPath, []byte("fake"), 0o600); err != nil {
		t.Fatalf("write fake keychain: %v", err)
	}
	if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/env bash\ncase \"$1\" in\ndefault-keychain) printf '\""+keychainPath+"\"\\n' ;;\n*) echo boom ; exit 1 ;;\nesac\n"), 0o755); err != nil {
		t.Fatalf("write fake security: %v", err)
	}
	t.Setenv("HASP_TEST_SECURITY_BIN", scriptPath)
	keyring := DarwinKeyring{}
	if err := keyring.Set(context.Background(), "svc", "acct", "value"); err == nil {
		t.Fatal("expected set failure")
	}
	if _, err := keyring.Get("svc", "acct"); err == nil {
		t.Fatal("expected get failure")
	}
	if err := keyring.Delete("svc", "acct"); err == nil {
		t.Fatal("expected delete failure")
	}
}

func TestDarwinKeyringGetAndDeleteFailWhenDefaultKeychainMissing(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "security")
	if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/env bash\nif [[ \"$1\" == \"default-keychain\" ]]; then\n  exit 1\nfi\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake security: %v", err)
	}
	t.Setenv("HASP_TEST_SECURITY_BIN", scriptPath)

	keyring := DarwinKeyring{}
	if _, err := keyring.Get("svc", "acct"); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected keyring unavailable from Get, got %v", err)
	}
	if err := keyring.Delete("svc", "acct"); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected keyring unavailable from Delete, got %v", err)
	}
}

func TestDarwinKeyringSetFailsAfterUsableKeychain(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "security")
	keychainPath := filepath.Join(tmpDir, "login.keychain-db")
	if err := os.WriteFile(keychainPath, []byte("fake"), 0o600); err != nil {
		t.Fatalf("write fake keychain: %v", err)
	}
	if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/env bash\ncase \"$1\" in\ndefault-keychain) printf '\""+keychainPath+"\"\\n' ;;\nadd-generic-password) echo 'set failed' ; exit 1 ;;\nesac\n"), 0o755); err != nil {
		t.Fatalf("write fake security: %v", err)
	}
	t.Setenv("HASP_TEST_SECURITY_BIN", scriptPath)

	keyring := DarwinKeyring{}
	if err := keyring.Set(context.Background(), "svc", "acct", "value"); err == nil || !strings.Contains(err.Error(), "set failed") {
		t.Fatalf("expected set failure after keychain check, got %v", err)
	}
}

func TestEnsureUsableDefaultKeychainBranches(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "security")

	t.Run("empty path", func(t *testing.T) {
		if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/env bash\nprintf '\\n'\n"), 0o755); err != nil {
			t.Fatalf("write fake security: %v", err)
		}
		t.Setenv("HASP_TEST_SECURITY_BIN", scriptPath)
		if err := ensureUsableDefaultKeychain(context.Background()); !errors.Is(err, ErrKeyringUnavailable) {
			t.Fatalf("expected unavailable on empty keychain path, got %v", err)
		}
	})

	t.Run("stat failure", func(t *testing.T) {
		if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/env bash\nprintf '\""+filepath.Join(tmpDir, "missing.keychain")+"\"\\n'\n"), 0o755); err != nil {
			t.Fatalf("write fake security: %v", err)
		}
		t.Setenv("HASP_TEST_SECURITY_BIN", scriptPath)
		if err := ensureUsableDefaultKeychain(context.Background()); !errors.Is(err, ErrKeyringUnavailable) {
			t.Fatalf("expected unavailable on missing keychain path, got %v", err)
		}
	})
}

func TestDefaultKeychainPathBranches(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "security")

	t.Run("default keychain command failure", func(t *testing.T) {
		if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/env bash\nexit 1\n"), 0o755); err != nil {
			t.Fatalf("write fake security: %v", err)
		}
		t.Setenv("HASP_TEST_SECURITY_BIN", scriptPath)
		if _, err := defaultKeychainPath(context.Background()); !errors.Is(err, ErrKeyringUnavailable) {
			t.Fatalf("expected unavailable default keychain error, got %v", err)
		}
	})
}

func TestSecurityBinaryPathUsesOverrideAndDefault(t *testing.T) {
	t.Setenv("HASP_TEST_SECURITY_BIN", "/tmp/custom-security")
	if got := securityBinaryPath(); got != "/tmp/custom-security" {
		t.Fatalf("security binary path = %q", got)
	}
	t.Setenv("HASP_TEST_SECURITY_BIN", "")
	if got := securityBinaryPath(); got != "/usr/bin/security" {
		t.Fatalf("default security binary path = %q", got)
	}
}
