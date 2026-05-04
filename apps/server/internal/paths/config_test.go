package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigPathAndRoundTrip(t *testing.T) {
	base := t.TempDir()
	origUserConfigDir := userConfigDir
	origRead := configReadFileFn
	origWrite := configWriteFileFn
	origMkdir := configMkdirAllFn
	defer func() {
		userConfigDir = origUserConfigDir
		configReadFileFn = origRead
		configWriteFileFn = origWrite
		configMkdirAllFn = origMkdir
	}()

	userConfigDir = func() (string, error) { return base, nil }
	configReadFileFn = os.ReadFile
	configWriteFileFn = os.WriteFile
	configMkdirAllFn = os.MkdirAll

	path, err := ConfigPath()
	if err != nil {
		t.Fatalf("config path: %v", err)
	}
	expected := filepath.Join(base, "hasp-cli.json")
	if path != expected {
		t.Fatalf("config path = %q, want %q", path, expected)
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load empty config: %v", err)
	}
	if cfg.HomeDir != "" {
		t.Fatalf("unexpected home dir in empty config: %q", cfg.HomeDir)
	}
	if cfg.AutoProtectRepos != nil || cfg.AutoInstallHooks != nil || cfg.DefaultCapturePolicy != "" {
		t.Fatalf("unexpected machine defaults in empty config: %+v", cfg)
	}

	wantHome := filepath.Join(t.TempDir(), "vault-home")
	autoProtect := true
	autoInstallHooks := false
	if err := SaveConfig(CLIConfig{
		HomeDir:              wantHome,
		AutoProtectRepos:     &autoProtect,
		AutoInstallHooks:     &autoInstallHooks,
		DefaultCapturePolicy: "session",
	}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	got, err := LoadConfig()
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if got.HomeDir != wantHome {
		t.Fatalf("home dir = %q, want %q", got.HomeDir, wantHome)
	}
	if got.AutoProtectRepos == nil || !*got.AutoProtectRepos {
		t.Fatalf("expected auto-protect default to round trip, got %+v", got)
	}
	if got.AutoInstallHooks == nil || *got.AutoInstallHooks {
		t.Fatalf("expected auto-install-hooks false to round trip, got %+v", got)
	}
	if got.DefaultCapturePolicy != "session" {
		t.Fatalf("default capture policy = %q, want session", got.DefaultCapturePolicy)
	}
}

func TestLoadAndSaveConfigTrimMachineDefaults(t *testing.T) {
	base := t.TempDir()
	origUserConfigDir := userConfigDir
	origRead := configReadFileFn
	origWrite := configWriteFileFn
	origMkdir := configMkdirAllFn
	defer func() {
		userConfigDir = origUserConfigDir
		configReadFileFn = origRead
		configWriteFileFn = origWrite
		configMkdirAllFn = origMkdir
	}()

	userConfigDir = func() (string, error) { return base, nil }
	configReadFileFn = os.ReadFile
	configWriteFileFn = os.WriteFile
	configMkdirAllFn = os.MkdirAll

	autoProtect := true
	autoInstallHooks := true
	if err := SaveConfig(CLIConfig{
		HomeDir:              "  /tmp/hasp-home  ",
		AutoProtectRepos:     &autoProtect,
		AutoInstallHooks:     &autoInstallHooks,
		DefaultCapturePolicy: "  auto  ",
	}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	got, err := LoadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if got.HomeDir != "/tmp/hasp-home" {
		t.Fatalf("trimmed home dir = %q", got.HomeDir)
	}
	if got.DefaultCapturePolicy != "auto" {
		t.Fatalf("trimmed default capture policy = %q", got.DefaultCapturePolicy)
	}
}

func TestLoadConfigPropagatesDecodeFailure(t *testing.T) {
	base := t.TempDir()
	origUserConfigDir := userConfigDir
	origRead := configReadFileFn
	defer func() {
		userConfigDir = origUserConfigDir
		configReadFileFn = origRead
	}()

	userConfigDir = func() (string, error) { return base, nil }
	configReadFileFn = os.ReadFile

	path := filepath.Join(base, "hasp-cli.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write broken config: %v", err)
	}

	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected config decode failure")
	}
}

func TestLoadConfigPropagatesReadFailure(t *testing.T) {
	base := t.TempDir()
	origUserConfigDir := userConfigDir
	origRead := configReadFileFn
	defer func() {
		userConfigDir = origUserConfigDir
		configReadFileFn = origRead
	}()

	userConfigDir = func() (string, error) { return base, nil }
	configReadFileFn = func(string) ([]byte, error) { return nil, fmt.Errorf("read fail") }
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected config read failure")
	}
}

func TestLoadConfigPropagatesConfigPathFailure(t *testing.T) {
	origUserConfigDir := userConfigDir
	defer func() { userConfigDir = origUserConfigDir }()

	userConfigDir = func() (string, error) { return "", fmt.Errorf("config dir fail") }
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected config path failure through LoadConfig")
	}
}

func TestSaveConfigPropagatesFailures(t *testing.T) {
	base := t.TempDir()
	origUserConfigDir := userConfigDir
	origRead := configReadFileFn
	origWrite := configWriteFileFn
	origMkdir := configMkdirAllFn
	defer func() {
		userConfigDir = origUserConfigDir
		configReadFileFn = origRead
		configWriteFileFn = origWrite
		configMkdirAllFn = origMkdir
	}()

	userConfigDir = func() (string, error) { return "", fmt.Errorf("config dir fail") }
	if _, err := ConfigPath(); err == nil {
		t.Fatal("expected config path failure")
	}
	if err := SaveConfig(CLIConfig{HomeDir: "/tmp/hasp"}); err == nil {
		t.Fatal("expected save config path failure")
	}

	userConfigDir = func() (string, error) { return base, nil }
	configMkdirAllFn = func(string, os.FileMode) error { return fmt.Errorf("mkdir fail") }
	if err := SaveConfig(CLIConfig{HomeDir: "/tmp/hasp"}); err == nil {
		t.Fatal("expected save config mkdir failure")
	}

	configMkdirAllFn = os.MkdirAll
	configWriteFileFn = func(string, []byte, os.FileMode) error { return fmt.Errorf("write fail") }
	if err := SaveConfig(CLIConfig{HomeDir: "/tmp/hasp"}); err == nil {
		t.Fatal("expected save config write failure")
	}
}
