//go:build integration

package evals

// Red-team integration test for hasp-x05.1.3: Onboarding eval.
// This test walks clean-install → setup (non-interactive, --json) →
// asserts brokered_proof.state=="ready" with no <repo> placeholder →
// executes the printed proof command and asserts exit 0 and non-empty
// HASP_SETUP_PROOF env var.
//
// The test MUST fail until the green team delivers state="ready" in the JSON
// output and the command produced is directly executable.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOnboardingEval(t *testing.T) {
	env := newEvalEnv(t)

	userHome := t.TempDir()
	haspHome := filepath.Join(t.TempDir(), "hasp-home")
	t.Cleanup(func() {
		stopEvalDaemon(t, env.withScopedHome(haspHome, userHome))
	})

	// Write a minimal import file so setup has a managed reference to bind.
	importPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(importPath, []byte("HASP_EVAL_SECRET=eval-value-12345\n"), 0o600); err != nil {
		t.Fatalf("write import env: %v", err)
	}

	// Augment PATH so the brokered proof command (which begins with a bare
	// "hasp" invocation) can find the built binary inside sh -c. This must
	// happen before commandEnv snapshots os.Environ() into cmdEnv.
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", filepath.Dir(env.binary)+":"+origPath)

	cmdEnv := env.commandEnv(map[string]string{
		"HOME":                      userHome,
		"HASP_HOME":                 haspHome,
		"XDG_CONFIG_HOME":           filepath.Join(userHome, ".config"),
		"HASP_EVAL_MASTER_PASSWORD": env.masterPassword,
		"HASP_MASTER_PASSWORD":      env.masterPassword,
	})

	// Run setup with --json so we can decode the structured output.
	stdout, stderr, err := runCmdWithInput(
		t,
		env.projectRoot,
		cmdEnv,
		"",
		env.binary,
		"setup",
		"--non-interactive",
		"--json",
		"--hasp-home", haspHome,
		"--agent", "codex-cli",
		"--master-password-env", "HASP_EVAL_MASTER_PASSWORD",
		"--repo", env.projectRoot,
		"--import", importPath,
		"--bind-imports",
		"--auto-protect-repos=false",
		"--enable-convenience-unlock=false",
		"--install-hooks=false",
	)
	if err != nil {
		t.Fatalf("setup command failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("decode setup JSON output: %v\nraw stdout:\n%s", err, stdout)
	}

	// Navigate verification.brokered_proof
	verification, ok := payload["verification"].(map[string]any)
	if !ok {
		t.Fatalf("expected verification map in setup output, got %T: %#v", payload["verification"], payload["verification"])
	}
	brokeredProof, ok := verification["brokered_proof"].(map[string]any)
	if !ok {
		t.Fatalf("expected verification.brokered_proof map, got %T: %#v", verification["brokered_proof"], verification["brokered_proof"])
	}

	// hasp-x05.1.2: state must be "ready" (not "unavailable") when imports are bound
	state, _ := brokeredProof["state"].(string)
	if state != "ready" {
		t.Fatalf("expected brokered_proof.state=%q after setup with --bind-imports, got %q (full brokeredProof: %#v)", "ready", state, brokeredProof)
	}

	// The proof command must not contain a <repo> placeholder
	proofCmd, _ := brokeredProof["command"].(string)
	if proofCmd == "" {
		t.Fatalf("expected brokered_proof.command to be non-empty, got %q", proofCmd)
	}
	if strings.Contains(proofCmd, "<repo>") {
		t.Fatalf("brokered_proof.command must not contain <repo> placeholder, got %q", proofCmd)
	}

	// hasp-x05.1.3: execute the printed proof command and assert exit 0 with
	// non-empty HASP_SETUP_PROOF.
	//
	// The command is a shell invocation; we run it via sh -c and capture output.
	// We replace the 'test -n "$HASP_SETUP_PROOF"' subcommand with one that
	// prints the value, so we can assert it's non-empty.
	proofCmdPrint := strings.Replace(
		proofCmd,
		`sh -c 'test -n "$HASP_SETUP_PROOF"'`,
		`sh -c 'printf "%s" "$HASP_SETUP_PROOF"'`,
		1,
	)
	runCmd := exec.Command("sh", "-c", proofCmdPrint)
	runCmd.Env = cmdEnv
	runCmd.Dir = env.projectRoot
	proofOut, proofErr := runCmd.CombinedOutput()
	if runCmd.ProcessState == nil || !runCmd.ProcessState.Success() {
		t.Fatalf("brokered proof command failed (exit non-0):\ncommand: %s\noutput: %s", proofCmdPrint, string(proofOut))
	}
	_ = proofErr
	if strings.TrimSpace(string(proofOut)) == "" {
		t.Fatalf("brokered proof command exited 0 but HASP_SETUP_PROOF was empty — secret was not injected into the subprocess environment")
	}
}
