package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSetupHelpersDirect(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	origLook := setupLookPathFn
	origExec := setupExecutableFn
	origHome := setupUserHomeDirFn
	origRead := setupReadFileFn
	origWrite := setupWriteFileFn
	origMkdir := setupMkdirAllFn
	origTempDir := setupTempDirFn
	defer func() {
		setupLookPathFn = origLook
		setupExecutableFn = origExec
		setupUserHomeDirFn = origHome
		setupReadFileFn = origRead
		setupWriteFileFn = origWrite
		setupMkdirAllFn = origMkdir
		setupTempDirFn = origTempDir
	}()
	setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
	setupTempDirFn = func() string { return filepath.Join(homeDir, "different-temp-root") }

	if got := setupAgentBinary("codex-cli"); got != "codex" {
		t.Fatalf("setupAgentBinary codex-cli = %q", got)
	}
	if got := setupAgentBinary("pi"); got != "pi" {
		t.Fatalf("setupAgentBinary pi = %q", got)
	}
	if got := setupAgentBinary("other"); got != "other" {
		t.Fatalf("setupAgentBinary passthrough = %q", got)
	}

	specs := []setupAgentSpec{{
		ID: "codex-cli", Label: "Codex CLI", ConfigPath: func(string) string {
			return filepath.Join(homeDir, ".codex", "config.toml")
		},
	}}
	if setupAnyExistingAgentConfig(specs) {
		t.Fatal("expected no existing agent config")
	}
	if err := os.MkdirAll(filepath.Dir(specs[0].ConfigPath("")), 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(specs[0].ConfigPath(""), []byte("x"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if !setupAnyExistingAgentConfig(specs) {
		t.Fatal("expected existing agent config")
	}

	setupLookPathFn = func(string) (string, error) { return "/usr/local/bin/hasp", nil }
	if got := setupHaspCommandPath(); got != "/usr/local/bin/hasp" {
		t.Fatalf("setupHaspCommandPath lookpath = %q", got)
	}
	setupLookPathFn = func(string) (string, error) { return "", errors.New("missing") }
	setupExecutableFn = func() (string, error) { return "/opt/bin/hasp", nil }
	if got := setupHaspCommandPath(); got != "/opt/bin/hasp" {
		t.Fatalf("setupHaspCommandPath executable = %q", got)
	}
	setupExecutableFn = func() (string, error) { return "/opt/bin/not-hasp", nil }
	if got := setupHaspCommandPath(); got != "hasp" {
		t.Fatalf("setupHaspCommandPath fallback = %q", got)
	}

	if _, err := setupAgentWrapperPath("", "claude-code"); err == nil {
		t.Fatal("expected missing hasp home error")
	}
	if _, err := setupAgentWrapperPath(filepath.Join(homeDir, ".hasp"), ""); err == nil {
		t.Fatal("expected missing agent id error")
	}
	wrapperPath, err := setupAgentWrapperPath(filepath.Join(homeDir, ".hasp"), "claude-code")
	if err != nil || !filepath.IsAbs(wrapperPath) {
		t.Fatalf("setupAgentWrapperPath = %q err=%v", wrapperPath, err)
	}

	setupReadFileFn = os.ReadFile
	setupWriteFileFn = os.WriteFile
	setupMkdirAllFn = os.MkdirAll
	installed, err := setupInstallAgentWrapper(filepath.Join(homeDir, ".hasp"), "/usr/local/bin/hasp", "claude-code")
	if err != nil {
		t.Fatalf("setupInstallAgentWrapper install: %v", err)
	}
	if data, err := os.ReadFile(installed); err != nil || !bytes.Contains(data, []byte("agent mcp")) || !bytes.Contains(data, []byte("find_hasp()")) || !bytes.Contains(data, []byte("HASP_AGENT_HASP")) {
		t.Fatalf("unexpected wrapper contents %q err=%v", string(data), err)
	}
	if second, err := setupInstallAgentWrapper(filepath.Join(homeDir, ".hasp"), "/usr/local/bin/hasp", "claude-code"); err != nil || second != installed {
		t.Fatalf("expected managed wrapper reuse, got %q err=%v", second, err)
	}
	unmanaged := filepath.Join(homeDir, ".hasp", "bin", "hasp-agent-cursor")
	if err := os.MkdirAll(filepath.Dir(unmanaged), 0o700); err != nil {
		t.Fatalf("mkdir unmanaged dir: %v", err)
	}
	if err := os.WriteFile(unmanaged, []byte("unmanaged"), 0o700); err != nil {
		t.Fatalf("write unmanaged wrapper: %v", err)
	}
	if _, err := setupInstallAgentWrapper(filepath.Join(homeDir, ".hasp"), "/usr/local/bin/hasp", "cursor"); err == nil {
		t.Fatal("expected unmanaged wrapper rejection")
	}

	haspHome := filepath.Join(homeDir, ".hasp")
	setupLookPathFn = func(string) (string, error) { return "/usr/local/bin/hasp", nil }
	setupExecutableFn = func() (string, error) { return "/usr/local/bin/hasp", nil }

	symlinkTarget := filepath.Join(homeDir, ".cursor", "target.json")
	symlinkPath := filepath.Join(homeDir, ".cursor", "symlink.json")
	if err := os.MkdirAll(filepath.Dir(symlinkTarget), 0o700); err != nil {
		t.Fatalf("mkdir symlink dir: %v", err)
	}
	if err := os.WriteFile(symlinkTarget, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Symlink(symlinkTarget, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := setupWriteAgentConfigs([]setupAgentSpec{{
		ID:         "claude-code",
		Format:     "json",
		ConfigPath: func(string) string { return symlinkPath },
	}}, haspHome); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}

	readFailPath := filepath.Join(homeDir, ".cursor", "read-fail.json")
	if err := os.WriteFile(readFailPath, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write read-fail config: %v", err)
	}
	setupReadFileFn = func(path string) ([]byte, error) {
		if path == readFailPath {
			return nil, errors.New("read fail")
		}
		return os.ReadFile(path)
	}
	if _, err := setupWriteAgentConfigs([]setupAgentSpec{{
		ID:         "claude-code",
		Format:     "json",
		ConfigPath: func(string) string { return readFailPath },
	}}, haspHome); err == nil || err.Error() != "read fail" {
		t.Fatalf("expected existing read failure, got %v", err)
	}
	setupReadFileFn = os.ReadFile

	blocker := filepath.Join(homeDir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write lstat blocker: %v", err)
	}
	if _, err := setupWriteAgentConfigs([]setupAgentSpec{{
		ID:         "claude-code",
		Format:     "json",
		ConfigPath: func(string) string { return filepath.Join(blocker, "child.json") },
	}}, haspHome); err == nil {
		t.Fatal("expected non-ENOENT lstat failure")
	}

	if _, err := setupWriteAgentConfigs([]setupAgentSpec{{
		ID:         "claude-code",
		Format:     "yaml",
		ConfigPath: func(string) string { return filepath.Join(homeDir, ".cursor", "config.yaml") },
	}}, haspHome); err == nil || !strings.Contains(err.Error(), "unsupported setup config format") {
		t.Fatalf("expected unsupported format failure, got %v", err)
	}

	t.Run("pi package config", func(t *testing.T) {
		piDir := filepath.Join(homeDir, "custom-pi-agent")
		t.Setenv("PI_CODING_AGENT_DIR", piDir)
		spec := setupAgentSpec{}
		for _, candidate := range setupSupportedAgents() {
			if candidate.ID == "pi" {
				spec = candidate
				break
			}
		}
		if spec.ID == "" {
			t.Fatal("expected pi setup agent")
		}
		outcomes, err := setupWriteAgentConfigs([]setupAgentSpec{spec}, haspHome)
		if err != nil {
			t.Fatalf("setup pi agent config: %v", err)
		}
		if len(outcomes) != 1 || outcomes[0].ConfigPath != filepath.Join(piDir, "settings.json") || !outcomes[0].Changed {
			t.Fatalf("unexpected pi setup outcome: %+v", outcomes)
		}
		settings, err := os.ReadFile(filepath.Join(piDir, "settings.json"))
		if err != nil {
			t.Fatalf("read pi settings: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(settings, &payload); err != nil {
			t.Fatalf("decode pi settings: %v", err)
		}
		packages, ok := payload["packages"].([]any)
		if !ok || len(packages) != 1 || packages[0] != setupPiPackagePath(haspHome) {
			t.Fatalf("expected generated pi package in settings, got %+v", payload)
		}
		extensionPath := filepath.Join(setupPiPackagePath(haspHome), "extensions", "hasp", "index.js")
		extension, err := os.ReadFile(extensionPath)
		if err != nil {
			t.Fatalf("read generated pi extension: %v", err)
		}
		if !bytes.Contains(extension, []byte("registerTool")) || !bytes.Contains(extension, []byte("tools/list")) || !bytes.Contains(extension, []byte("hasp-agent-pi")) {
			t.Fatalf("generated pi extension missing expected bridge code: %s", string(extension))
		}
		rerun, err := setupWriteAgentConfigs([]setupAgentSpec{spec}, haspHome)
		if err != nil {
			t.Fatalf("rerun setup pi agent config: %v", err)
		}
		if len(rerun) != 1 || rerun[0].Changed {
			t.Fatalf("expected idempotent pi settings write, got %+v", rerun)
		}
	})

	notes := setupNotes(specs, true, setupOptions{BindImports: true}, "unavailable", "detail")
	if len(notes) == 0 {
		t.Fatal("expected setup notes")
	}
	steps := setupNextSteps(filepath.Join(homeDir, "repo"), store.Binding{Aliases: map[string]string{"secret_01": "API_TOKEN"}}, filepath.Join(homeDir, ".hasp"), "unavailable", "detail", true, true)
	if len(steps) == 0 {
		t.Fatal("expected setup next steps")
	}

	if !setupSavedHomeLooksUsable(filepath.Join(homeDir, ".hasp")) {
		t.Fatal("expected saved home to look usable")
	}
	if setupSavedHomeLooksUsable(filepath.Join(os.TempDir(), "ephemeral-hasp")) {
		t.Fatal("expected temp-root home to be rejected")
	}

	origGOOS := setupGOOS
	defer func() { setupGOOS = origGOOS }()
	setupGOOS = "darwin"
	if !defaultSetupConvenienceUnlock() {
		t.Fatal("expected darwin convenience unlock default")
	}
	setupGOOS = "linux"
	if defaultSetupConvenienceUnlock() {
		t.Fatal("expected non-darwin convenience unlock default false")
	}

	if ptr := setupBoolPointer(true); ptr == nil || !*ptr {
		t.Fatal("expected bool pointer")
	}
	if value, err := expandHome("~/repo"); err != nil || !filepath.IsAbs(value) {
		t.Fatalf("expandHome = %q err=%v", value, err)
	}
	if !withinPath(filepath.Join(homeDir, "repo", "x"), filepath.Join(homeDir, "repo")) {
		t.Fatal("expected withinPath true")
	}
	if withinPath(filepath.Join(homeDir, "other"), filepath.Join(homeDir, "repo")) {
		t.Fatal("expected withinPath false")
	}
}

func TestSetupAgentWrapperFallsBackWhenConfiguredHaspMoved(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	haspHome := filepath.Join(homeDir, ".hasp")
	origRead := setupReadFileFn
	origWrite := setupWriteFileFn
	origMkdir := setupMkdirAllFn
	defer func() {
		setupReadFileFn = origRead
		setupWriteFileFn = origWrite
		setupMkdirAllFn = origMkdir
	}()
	setupReadFileFn = os.ReadFile
	setupWriteFileFn = os.WriteFile
	setupMkdirAllFn = os.MkdirAll

	wrapper, err := setupInstallAgentWrapper(haspHome, filepath.Join(homeDir, "missing", "hasp"), "codex-cli")
	if err != nil {
		t.Fatalf("install wrapper: %v", err)
	}
	fakeBin := filepath.Join(homeDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o700); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fakeHasp := filepath.Join(fakeBin, "hasp")
	if err := os.WriteFile(fakeHasp, []byte("#!/usr/bin/env bash\nprintf '%s\\n' \"$*\"\n"), 0o700); err != nil {
		t.Fatalf("write fake hasp: %v", err)
	}

	cmd := exec.Command(wrapper, "--probe")
	cmd.Env = append(os.Environ(), "PATH="+strings.Join([]string{fakeBin, "/bin", "/usr/bin"}, string(os.PathListSeparator)))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run wrapper: %v: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "agent mcp codex-cli --probe" {
		t.Fatalf("wrapper did not fall back through PATH, got %q", got)
	}
}
