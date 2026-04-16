//go:build integration

package evals

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackagedArtifactOperatorEval(t *testing.T) {
	root := repoRoot(t)
	releaseEnv := os.Environ()
	tarball, _ := runCmd(t, root, releaseEnv, "bash", "-lc", `
export GNUPGHOME="$(mktemp -d)"
trap 'rm -rf "$GNUPGHOME"' EXIT
export HASP_ALLOW_EPHEMERAL_RELEASE_SIGNING=1
unset HASP_RELEASE_GPG_KEY_ID
./scripts/package-release.sh
`)
	artifactDir := t.TempDir()
	runCmd(t, artifactDir, nil, "tar", "-xzf", strings.TrimSpace(tarball))
	entries, err := os.ReadDir(artifactDir)
	if err != nil {
		t.Fatalf("read artifact dir: %v", err)
	}
	var artifactRoot string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "hasp_") {
			artifactRoot = filepath.Join(artifactDir, entry.Name())
			break
		}
	}
	if artifactRoot == "" {
		t.Fatal("artifact root not found")
	}
	if _, err := os.Stat(filepath.Join(artifactRoot, "scripts", "hasp-install-hooks.sh")); err != nil {
		t.Fatalf("missing packaged install-hooks script: %v", err)
	}
	if _, err := os.Stat(filepath.Join(artifactRoot, "LICENSE")); err != nil {
		t.Fatalf("missing packaged license artifact: %v", err)
	}
	if _, err := os.Stat(filepath.Join(artifactRoot, "agent-profiles", "README.md")); err != nil {
		t.Fatalf("missing packaged agent profile index: %v", err)
	}

	projectRoot := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	initGitRepo(t, projectRoot)

	env := map[string]string{
		"HASP_HOME":              t.TempDir(),
		"HASP_SOCKET":            filepath.Join("/tmp", "hasp-artifact.sock"),
		"HASP_MASTER_PASSWORD":   "artifact-master-password",
		"HASP_BACKUP_PASSPHRASE": "artifact-backup-passphrase",
	}
	cmdEnv := os.Environ()
	for key, value := range env {
		cmdEnv = append(cmdEnv, key+"="+value)
	}

	bootstrapOut, _ := runCmd(t, projectRoot, cmdEnv, filepath.Join(artifactRoot, "bin", "hasp"), "bootstrap", "--profile", "claude-code", "--project-root", projectRoot, "--hooks=false")
	if !strings.Contains(bootstrapOut, "\"claude-code\"") {
		t.Fatalf("artifact bootstrap missing profile output: %s", bootstrapOut)
	}
	runCmd(t, projectRoot, cmdEnv, filepath.Join(artifactRoot, "bin", "hasp"), "set", "--name", "api_token", "--value", "abc123")
	runCmd(t, projectRoot, cmdEnv, filepath.Join(artifactRoot, "bin", "hasp"), "bootstrap", "--profile", "claude-code", "--project-root", projectRoot, "--hooks=false", "--bind-item", "api_token", "--verify=false")
	runCmd(t, projectRoot, cmdEnv, filepath.Join(artifactRoot, "scripts", "hasp-install-hooks.sh"))

	readmePath := filepath.Join(projectRoot, "README.md")
	if err := os.WriteFile(readmePath, []byte("ok\n"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	runCmd(t, projectRoot, cmdEnv, "git", "add", "README.md")
	runCmd(t, projectRoot, cmdEnv, "git", "commit", "-m", "clean")

	secretPath := filepath.Join(projectRoot, ".env.local")
	if err := os.WriteFile(secretPath, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	runCmd(t, projectRoot, cmdEnv, "git", "add", ".env.local")
	if _, _, err := runCmdWithInput(t, projectRoot, cmdEnv, "", "git", "commit", "-m", "should-fail"); err == nil {
		t.Fatal("expected pre-commit hook to block managed secret commit")
	}

	overrideEnv := append([]string{}, cmdEnv...)
	overrideEnv = append(overrideEnv, "HASP_ALLOW_MANAGED_SECRETS=1")
	runCmd(t, projectRoot, overrideEnv, "git", "commit", "-m", "allowed")

	bareRemote := filepath.Join(t.TempDir(), "remote.git")
	runCmd(t, "", nil, "git", "init", "--bare", bareRemote)
	runCmd(t, projectRoot, cmdEnv, "git", "remote", "add", "origin", bareRemote)
	branchOut, _ := runCmd(t, projectRoot, cmdEnv, "git", "branch", "--show-current")
	branch := strings.TrimSpace(branchOut)
	if _, _, err := runCmdWithInput(t, projectRoot, cmdEnv, "", "git", "push", "origin", branch); err == nil {
		t.Fatal("expected pre-push hook to block managed secret push")
	}
	runCmd(t, projectRoot, overrideEnv, "git", "push", "origin", branch)

	if _, _, err := runCmdWithInput(t, projectRoot, cmdEnv, "", filepath.Join(artifactRoot, "scripts", "hasp-deploy.sh"), projectRoot, "--", "true"); err == nil {
		t.Fatal("expected packaged deploy script to block managed secret deploy")
	}
	runCmd(t, projectRoot, overrideEnv, filepath.Join(artifactRoot, "scripts", "hasp-deploy.sh"), projectRoot, "--", "true")

	mcpInput := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n"
	mcpOut, _, err := runCmdWithInput(t, projectRoot, cmdEnv, mcpInput, filepath.Join(artifactRoot, "bin", "hasp"), "mcp")
	if err != nil {
		t.Fatalf("artifact mcp failed: %v", err)
	}
	if !strings.Contains(mcpOut, "hasp_list") {
		t.Fatalf("artifact mcp missing tools/list response: %s", mcpOut)
	}
}
