//go:build integration

package evals

// Integration eval for hasp-x05.2.3: generic-compatible first proof.
//
// This test validates the generic-compatible surface end-to-end using the
// codex-cli setup path (approach a), because hasp setup does not accept
// --agent generic-compatible directly in V1.  The generic-compatible tier
// is a first-proof surface exposed through:
//   - hasp agent list-supported  (includes generic-compatible with setup/doctor/proof commands)
//   - hasp bootstrap print-config generic-compatible  (prints ready-to-paste snippets)
//   - hasp run  (executes the brokered proof command printed by setup)
//
// Acceptance:
//   - hasp agent list-supported --json includes generic-compatible with non-empty
//     setup_command, doctor_command, first_proof_command, and print_config.
//   - hasp bootstrap print-config generic-compatible --format stdio-json prints
//     output that includes "generic-compatible" and parses as JSON.
//   - After setup with --agent codex-cli, brokered_proof.state == "ready".
//   - The brokered proof command executes successfully, and the HASP_SETUP_PROOF
//     env var is non-empty (managed value was injected into the subprocess).

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenericCompatibleFirstProof(t *testing.T) {
	env := newEvalEnv(t)

	userHome := t.TempDir()
	haspHome := filepath.Join(t.TempDir(), "hasp-home")
	t.Cleanup(func() {
		stopEvalDaemon(t, env.withScopedHome(haspHome, userHome))
	})

	// Write a minimal import file so setup has a managed reference to bind.
	importPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(importPath, []byte("HASP_EVAL_GENERIC=generic-proof-42\n"), 0o600); err != nil {
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

	// PART 1: Run setup with --agent codex-cli so that the vault is initialized,
	// the repo is bound, and imports are bound.  This is the codex-cli path (a):
	// we validate the generic-compatible surface separately below.
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

	// Navigate verification.brokered_proof.
	verification, ok := payload["verification"].(map[string]any)
	if !ok {
		t.Fatalf("expected verification map in setup output, got %T: %#v", payload["verification"], payload["verification"])
	}
	brokeredProof, ok := verification["brokered_proof"].(map[string]any)
	if !ok {
		t.Fatalf("expected verification.brokered_proof map, got %T: %#v", verification["brokered_proof"], verification["brokered_proof"])
	}

	state, _ := brokeredProof["state"].(string)
	if state != "ready" {
		t.Fatalf("expected brokered_proof.state=%q after setup with --bind-imports, got %q (brokeredProof: %#v)", "ready", state, brokeredProof)
	}

	proofCmd, _ := brokeredProof["command"].(string)
	if proofCmd == "" {
		t.Fatalf("expected brokered_proof.command to be non-empty")
	}
	if strings.Contains(proofCmd, "<repo>") {
		t.Fatalf("brokered_proof.command must not contain <repo> placeholder, got %q", proofCmd)
	}

	// PART 2: Execute the brokered proof command.
	// Replace the 'test -n "$HASP_SETUP_PROOF"' check with a printf so we can
	// capture and assert the injected value is non-empty.
	proofCmdPrint := strings.Replace(
		proofCmd,
		`sh -c 'test -n "$HASP_SETUP_PROOF"'`,
		`sh -c 'printf "%s" "$HASP_SETUP_PROOF"'`,
		1,
	)
	runCmd := exec.Command("sh", "-c", proofCmdPrint)
	runCmd.Env = cmdEnv
	runCmd.Dir = env.projectRoot
	proofOut, _ := runCmd.CombinedOutput()
	if runCmd.ProcessState == nil || !runCmd.ProcessState.Success() {
		t.Fatalf("brokered proof command failed (exit non-0):\ncommand: %s\noutput: %s", proofCmdPrint, string(proofOut))
	}
	if strings.TrimSpace(string(proofOut)) == "" {
		t.Fatalf("brokered proof command exited 0 but HASP_SETUP_PROOF was empty — secret was not injected")
	}

	// PART 3: Assert hasp agent list-supported --json includes generic-compatible
	// with the required fields from subtask 2.2.
	listOut, listErr, err := runCmdWithInput(
		t,
		env.projectRoot,
		cmdEnv,
		"",
		env.binary,
		"agent", "list-supported", "--json",
	)
	if err != nil {
		t.Fatalf("agent list-supported failed: %v\nstdout:\n%s\nstderr:\n%s", err, listOut, listErr)
	}

	var listPayload map[string]any
	if err := json.Unmarshal([]byte(listOut), &listPayload); err != nil {
		t.Fatalf("decode agent list-supported output: %v\nraw:\n%s", err, listOut)
	}
	profiles, ok := listPayload["profiles"].([]any)
	if !ok {
		t.Fatalf("expected profiles array in agent list-supported output: %#v", listPayload)
	}

	var genericProfile map[string]any
	for _, p := range profiles {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if pm["id"] == "generic" || pm["support_tier"] == "generic-compatible" {
			genericProfile = pm
			break
		}
	}
	if genericProfile == nil {
		t.Fatalf("generic-compatible profile not found in agent list-supported output: %#v", profiles)
	}
	if genericProfile["support_tier"] != "generic-compatible" {
		t.Fatalf("expected support_tier=generic-compatible, got %v", genericProfile["support_tier"])
	}
	if genericProfile["first_class"] != false {
		t.Fatalf("expected first_class=false for generic-compatible, got %v", genericProfile["first_class"])
	}

	// setup_command, doctor_command, first_proof_command must be non-empty.
	for _, field := range []string{"setup_command", "doctor_command", "first_proof_command"} {
		v, _ := genericProfile[field].(string)
		if strings.TrimSpace(v) == "" {
			t.Fatalf("expected generic-compatible profile to have non-empty %q, got %q (full profile: %#v)", field, v, genericProfile)
		}
	}

	// print_config must be a non-empty map.
	printConfig, ok := genericProfile["print_config"].(map[string]any)
	if !ok || len(printConfig) == 0 {
		t.Fatalf("expected generic-compatible print_config to be a non-empty map, got %T: %#v", genericProfile["print_config"], genericProfile["print_config"])
	}

	// PART 4: hasp bootstrap print-config generic-compatible --format stdio-json
	// must output valid JSON that includes "generic-compatible".
	pcOut, pcErr, err := runCmdWithInput(
		t,
		env.projectRoot,
		cmdEnv,
		"",
		env.binary,
		"bootstrap", "print-config", "generic-compatible", "--format", "stdio-json",
	)
	if err != nil {
		t.Fatalf("bootstrap print-config failed: %v\nstdout:\n%s\nstderr:\n%s", err, pcOut, pcErr)
	}
	if !strings.Contains(pcOut, "generic-compatible") {
		t.Fatalf("bootstrap print-config output does not include 'generic-compatible': %s", pcOut)
	}
	var pcJSON map[string]any
	if err := json.Unmarshal([]byte(pcOut), &pcJSON); err != nil {
		t.Fatalf("bootstrap print-config stdio-json output does not parse as JSON: %v\nraw:\n%s", err, pcOut)
	}
}
