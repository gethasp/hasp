//go:build integration

package evals

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupCommandEvalPublishesConcreteFirstProofSteps(t *testing.T) {
	env := newEvalEnv(t)

	userHome := t.TempDir()
	haspHome := filepath.Join(t.TempDir(), "hasp-home")
	t.Cleanup(func() {
		stopEvalDaemon(t, env.withScopedHome(haspHome, userHome))
	})
	importPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(importPath, []byte("OPENAI_API_KEY=abc123\n"), 0o600); err != nil {
		t.Fatalf("write import path: %v", err)
	}

	cmdEnv := env.commandEnv(map[string]string{
		"HOME":                  userHome,
		"HASP_HOME":             haspHome,
		"XDG_CONFIG_HOME":       filepath.Join(userHome, ".config"),
		"SETUP_MASTER_PASSWORD": env.masterPassword,
	})

	stdout, stderr, err := runCmdWithInput(
		t,
		env.projectRoot,
		cmdEnv,
		"",
		env.binary,
		"setup",
		"--non-interactive",
		"--hasp-home", haspHome,
		"--repo", env.projectRoot,
		"--agent", "codex-cli",
		"--master-password-env", "SETUP_MASTER_PASSWORD",
		"--import", importPath,
		"--bind-imports",
		"--install-hooks=false",
		"--enable-convenience-unlock=false",
	)
	if err != nil {
		t.Fatalf("setup command failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("decode setup output: %v", err)
	}

	nextSteps, ok := payload["next_steps"].([]any)
	if !ok || len(nextSteps) == 0 {
		t.Fatalf("expected next_steps in setup output: %#v", payload)
	}
	joinedSteps := make([]string, 0, len(nextSteps))
	for _, raw := range nextSteps {
		step, ok := raw.(string)
		if !ok {
			t.Fatalf("expected next step string, got %#v", raw)
		}
		joinedSteps = append(joinedSteps, step)
	}
	joined := strings.Join(joinedSteps, "\n")
	for _, want := range []string{
		`verify MCP with: printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp`,
		`review the repo binding with: hasp project status --project-root "`,
		`run a brokered proof command: hasp run --project-root "`,
		`future CLI commands still need HASP_MASTER_PASSWORD because convenience unlock is not active`,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("setup next steps missing %q in %q", want, joined)
		}
	}

	notes, ok := payload["notes"].([]any)
	if !ok || len(notes) == 0 {
		t.Fatalf("expected setup notes in output: %#v", payload)
	}
	joinedNotes := make([]string, 0, len(notes))
	for _, raw := range notes {
		note, ok := raw.(string)
		if !ok {
			t.Fatalf("expected setup note string, got %#v", raw)
		}
		joinedNotes = append(joinedNotes, note)
	}
	if !strings.Contains(strings.Join(joinedNotes, "\n"), "setup never writes secret values into agent config, repo files, or shell profiles") {
		t.Fatalf("expected first-proof safety note in setup output, got %#v", joinedNotes)
	}
}

func TestSetupCommandEvalReportsUnavailableBrokeredProofWithoutBoundRefs(t *testing.T) {
	env := newEvalEnv(t)

	userHome := t.TempDir()
	haspHome := filepath.Join(t.TempDir(), "hasp-home")
	t.Cleanup(func() {
		stopEvalDaemon(t, env.withScopedHome(haspHome, userHome))
	})

	cmdEnv := env.commandEnv(map[string]string{
		"HOME":                  userHome,
		"HASP_HOME":             haspHome,
		"XDG_CONFIG_HOME":       filepath.Join(userHome, ".config"),
		"SETUP_MASTER_PASSWORD": env.masterPassword,
	})

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
		"--repo", env.projectRoot,
		"--agent", "codex-cli",
		"--master-password-env", "SETUP_MASTER_PASSWORD",
		"--install-hooks=false",
		"--enable-convenience-unlock=false",
	)
	if err != nil {
		t.Fatalf("setup command without bound refs failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("decode setup output: %v", err)
	}
	verification, ok := payload["verification"].(map[string]any)
	if !ok {
		t.Fatalf("expected verification object, got %#v", payload["verification"])
	}
	brokeredProof, ok := verification["brokered_proof"].(map[string]any)
	if !ok {
		t.Fatalf("expected brokered_proof object, got %#v", verification["brokered_proof"])
	}
	if brokeredProof["ready"] != false || brokeredProof["reason"] != "no brokered reference available yet" {
		t.Fatalf("unexpected unavailable brokered proof payload: %#v", brokeredProof)
	}
}
