package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestSetupPiAgentConfigDirVariants(t *testing.T) {
	homeDir := filepath.Join(t.TempDir(), "home")
	if got := setupPiAgentConfigDir(homeDir); got != filepath.Join(homeDir, ".pi", "agent") {
		t.Fatalf("default pi config dir = %q", got)
	}
	t.Setenv("PI_CODING_AGENT_DIR", "~")
	if got := setupPiAgentConfigDir(homeDir); got != homeDir {
		t.Fatalf("home pi config dir = %q", got)
	}
	t.Setenv("PI_CODING_AGENT_DIR", "~/custom-pi")
	if got := setupPiAgentConfigDir(homeDir); got != filepath.Join(homeDir, "custom-pi") {
		t.Fatalf("home-relative pi config dir = %q", got)
	}
	absolute := filepath.Join(t.TempDir(), "pi-agent")
	t.Setenv("PI_CODING_AGENT_DIR", absolute)
	if got := setupPiAgentConfigDir(homeDir); got != absolute {
		t.Fatalf("absolute pi config dir = %q", got)
	}
}

func TestSetupInstallPiPackageFailures(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	haspHome := filepath.Join(homeDir, ".hasp")
	origMkdir := setupMkdirAllFn
	origWrite := setupWriteFileFn
	defer func() {
		setupMkdirAllFn = origMkdir
		setupWriteFileFn = origWrite
	}()

	setupMkdirAllFn = func(path string, mode os.FileMode) error {
		if strings.Contains(path, "pi-package") {
			return errors.New("mkdir pi fail")
		}
		return os.MkdirAll(path, mode)
	}
	if _, err := setupInstallPiPackage(haspHome, "/bin/hasp-agent-pi", "pi"); err == nil || err.Error() != "mkdir pi fail" {
		t.Fatalf("expected pi mkdir failure, got %v", err)
	}

	setupMkdirAllFn = os.MkdirAll
	setupWriteFileFn = func(path string, _ []byte, _ os.FileMode) error {
		if filepath.Base(path) == "package.json" {
			return errors.New("package write fail")
		}
		return nil
	}
	if _, err := setupInstallPiPackage(haspHome, "/bin/hasp-agent-pi", "pi"); err == nil || err.Error() != "package write fail" {
		t.Fatalf("expected package write failure, got %v", err)
	}

	setupWriteFileFn = func(path string, data []byte, mode os.FileMode) error {
		if filepath.Base(path) == "index.js" {
			return errors.New("extension write fail")
		}
		return os.WriteFile(path, data, mode)
	}
	if _, err := setupInstallPiPackage(haspHome, "/bin/hasp-agent-pi", "pi"); err == nil || err.Error() != "extension write fail" {
		t.Fatalf("expected extension write failure, got %v", err)
	}
}

func TestSetupWritePiAgentConfigFailureBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	origLook := setupLookPathFn
	origExec := setupExecutableFn
	origRead := setupReadFileFn
	origWrite := setupWriteFileFn
	origMkdir := setupMkdirAllFn
	origRename := setupRenameFn
	origCreateTemp := setupCreateTempFn
	defer func() {
		setupLookPathFn = origLook
		setupExecutableFn = origExec
		setupReadFileFn = origRead
		setupWriteFileFn = origWrite
		setupMkdirAllFn = origMkdir
		setupRenameFn = origRename
		setupCreateTempFn = origCreateTemp
	}()

	reset := func() {
		setupLookPathFn = func(string) (string, error) { return "/usr/local/bin/hasp", nil }
		setupExecutableFn = func() (string, error) { return "/usr/local/bin/hasp", nil }
		setupReadFileFn = os.ReadFile
		setupWriteFileFn = os.WriteFile
		setupMkdirAllFn = os.MkdirAll
		setupRenameFn = os.Rename
		setupCreateTempFn = os.CreateTemp
	}
	specFor := func(configPath string) setupAgentSpec {
		return setupAgentSpec{
			ID:         "pi",
			Label:      "Pi",
			Format:     "pi-package",
			ConfigPath: func(string) string { return configPath },
		}
	}
	runWrite := func(configPath string) error {
		_, err := setupWriteAgentConfigs([]setupAgentSpec{specFor(configPath)}, filepath.Join(t.TempDir(), "hasp-home"))
		return err
	}

	reset()
	setupMkdirAllFn = func(path string, mode os.FileMode) error {
		if strings.Contains(path, "pi-package") {
			return errors.New("pi package install fail")
		}
		return os.MkdirAll(path, mode)
	}
	if err := runWrite(filepath.Join(homeDir, "pi-settings.json")); err == nil || err.Error() != "pi package install fail" {
		t.Fatalf("expected pi package install failure, got %v", err)
	}

	reset()
	symlinkTarget := filepath.Join(homeDir, "target-settings.json")
	symlinkPath := filepath.Join(homeDir, "symlink-settings.json")
	if err := os.WriteFile(symlinkTarget, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Symlink(symlinkTarget, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if err := runWrite(symlinkPath); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected pi symlink rejection, got %v", err)
	}

	reset()
	readFailPath := filepath.Join(homeDir, "read-fail-settings.json")
	if err := os.WriteFile(readFailPath, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write read fail settings: %v", err)
	}
	setupReadFileFn = func(path string) ([]byte, error) {
		if path == readFailPath {
			return nil, errors.New("pi read fail")
		}
		return os.ReadFile(path)
	}
	if err := runWrite(readFailPath); err == nil || err.Error() != "pi read fail" {
		t.Fatalf("expected pi read failure, got %v", err)
	}

	reset()
	blocker := filepath.Join(homeDir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if err := runWrite(filepath.Join(blocker, "settings.json")); err == nil {
		t.Fatal("expected pi lstat failure")
	}

	reset()
	invalidPackagesPath := filepath.Join(homeDir, "invalid-packages.json")
	if err := os.WriteFile(invalidPackagesPath, []byte(`{"packages":true}`), 0o600); err != nil {
		t.Fatalf("write invalid packages settings: %v", err)
	}
	if err := runWrite(invalidPackagesPath); err == nil || !strings.Contains(err.Error(), "packages value is not an array") {
		t.Fatalf("expected pi upsert failure, got %v", err)
	}

	reset()
	setupCreateTempFn = func(string, string) (*os.File, error) {
		return nil, errors.New("pi atomic fail")
	}
	if err := runWrite(filepath.Join(homeDir, "atomic-fail-settings.json")); err == nil || err.Error() != "pi atomic fail" {
		t.Fatalf("expected pi atomic failure, got %v", err)
	}
}

func TestPiSettingsConfigParseBranches(t *testing.T) {
	packagePath := filepath.Join(t.TempDir(), "pi-package")
	if _, err := upsertPiSettingsPackageConfig([]byte("{bad json"), packagePath); err == nil {
		t.Fatal("expected malformed pi settings upsert failure")
	}
	if data, err := removePiSettingsPackageConfig([]byte(`{"defaultModel":"sonnet"}`), packagePath); err != nil || !strings.Contains(string(data), "defaultModel") {
		t.Fatalf("expected pi removal without packages to preserve settings, got %q err=%v", string(data), err)
	}
	if _, err := removePiSettingsPackageConfig([]byte("{bad json"), packagePath); err == nil {
		t.Fatal("expected malformed pi settings removal failure")
	}
	withMixedPackages := []byte(`{"packages":["/other/pkg",42]}`)
	if data, err := removePiSettingsPackageConfig(withMixedPackages, packagePath); err != nil || !strings.Contains(string(data), "/other/pkg") || !strings.Contains(string(data), "42") {
		t.Fatalf("expected pi removal to keep non-matching entries, got %q err=%v", string(data), err)
	}
}

func TestRemovePiAgentConsumerConfigFailures(t *testing.T) {
	lockAppSeams(t)

	origRead := setupReadFileFn
	origAtomic := agentAtomicWriteFn
	origResolvePaths := appResolvePathsFn
	defer func() {
		setupReadFileFn = origRead
		agentAtomicWriteFn = origAtomic
		appResolvePathsFn = origResolvePaths
	}()

	setupReadFileFn = os.ReadFile
	configPath := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(configPath, []byte(`{"packages":["/x"]}`), 0o600); err != nil {
		t.Fatalf("write pi settings: %v", err)
	}
	appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{}, errors.New("resolve pi home fail") }
	if err := removeAgentConsumerConfig(setupAgentSpec{Format: "pi-package"}, configPath); err == nil || err.Error() != "resolve pi home fail" {
		t.Fatalf("expected pi resolve failure, got %v", err)
	}

	appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{HomeDir: t.TempDir()}, nil }
	if err := os.WriteFile(configPath, []byte(`{"packages":true}`), 0o600); err != nil {
		t.Fatalf("write invalid pi settings: %v", err)
	}
	if err := removeAgentConsumerConfig(setupAgentSpec{Format: "pi-package"}, configPath); err == nil || !strings.Contains(err.Error(), "packages value is not an array") {
		t.Fatalf("expected pi removal parse failure, got %v", err)
	}
}
