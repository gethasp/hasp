//go:build integration

package evals

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/profiles"
)

func TestBootstrapDoctorEval(t *testing.T) {
	env := newEvalEnv(t)
	importPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(importPath, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write import file: %v", err)
	}

	stdout, _, err := runHasp(t, env, "", "bootstrap", "doctor", "--json", "--profile", "claude-code", "--project-root", env.projectRoot, "--import", importPath)
	if err != nil {
		t.Fatalf("bootstrap doctor failed: %v", err)
	}
	if strings.Contains(stdout, "API_TOKEN") || strings.Contains(stdout, "abc123") {
		t.Fatalf("doctor output leaked import detail: %s", stdout)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("decode bootstrap doctor output: %v", err)
	}
	if payload["support_tier"] != profiles.SupportTierFirstClassShipped {
		t.Fatalf("unexpected support tier: %v", payload)
	}
	checks := payload["checks"].(map[string]any)
	for _, key := range []string{"master_password", "project_root", "vault", "release_gate"} {
		if _, ok := checks[key]; !ok {
			t.Fatalf("expected check %q in %v", key, checks)
		}
	}
	if _, ok := payload["ready"]; ok {
		t.Fatalf("doctor output should not collapse to a blanket ready bit: %v", payload)
	}
	genericPath := payload["generic_path"].(map[string]any)
	if genericPath["first_class"] != false || genericPath["compatibility_label"] != profiles.CompatibilityLabelGeneric {
		t.Fatalf("unexpected generic path metadata: %+v", genericPath)
	}
	convenience := payload["convenience_mode"].(map[string]any)
	if convenience["compatibility_label"] != profiles.CompatibilityLabelConvenience {
		t.Fatalf("unexpected convenience metadata: %+v", convenience)
	}
}

func TestBootstrapImportBindEval(t *testing.T) {
	env := newEvalEnv(t)
	importPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(importPath, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write import file: %v", err)
	}

	stdout, _, err := runHasp(t, env, "", "bootstrap", "--json", "--profile", "claude-code", "--project-root", env.projectRoot, "--hooks=false", "--import", importPath, "--bind-imports")
	if err != nil {
		t.Fatalf("bootstrap import/bind failed: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("decode bootstrap output: %v", err)
	}
	if payload["support_tier"] != profiles.SupportTierFirstClassShipped {
		t.Fatalf("unexpected support tier: %v", payload)
	}
	imported, ok := payload["imported"].([]any)
	if !ok || len(imported) == 0 {
		t.Fatalf("expected imported items in bootstrap output: %v", payload)
	}
	aliases := payload["bound_aliases"].(map[string]any)
	if len(aliases) == 0 {
		t.Fatalf("expected bound aliases after import bootstrap: %v", payload)
	}

	statusOut, _, err := runHasp(t, env, "", "project", "status", "--project-root", env.projectRoot)
	if err != nil {
		t.Fatalf("project status failed: %v", err)
	}
	if !strings.Contains(statusOut, "secret_01") {
		t.Fatalf("expected bound alias in project status: %s", statusOut)
	}
}

func TestBootstrapGenericPathEval(t *testing.T) {
	env := newEvalEnv(t)
	stdout, _, err := runHasp(t, env, "", "bootstrap", "generic", "--json", "--project-root", env.projectRoot, "--hooks=false")
	if err != nil {
		t.Fatalf("generic bootstrap failed: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("decode generic bootstrap output: %v", err)
	}
	if payload["support_tier"] != profiles.SupportTierGenericCompatible || payload["first_class"] != false {
		t.Fatalf("unexpected generic bootstrap metadata: %v", payload)
	}
	profile := payload["profile"].(map[string]any)
	if profile["id"] != "generic" {
		t.Fatalf("expected generic profile id, got %v", profile)
	}
}

func TestImportPreviewFromStdinEval(t *testing.T) {
	env := newEvalEnv(t)
	stdout, _, err := runCmdWithInput(
		t,
		env.projectRoot,
		env.commandEnv(nil),
		"export API_TOKEN=abc123\n",
		env.binary,
		"import",
		"--json",
		"--preview",
		"--format",
		"env",
		"-",
	)
	if err != nil {
		t.Fatalf("stdin import preview failed: %v", err)
	}
	if strings.Contains(stdout, "abc123") {
		t.Fatalf("preview leaked imported value: %s", stdout)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("decode import preview output: %v", err)
	}
	if payload["applied"] != false {
		t.Fatalf("expected preview-only import to report applied=false: %v", payload)
	}
	preview := payload["preview"].(map[string]any)
	if preview["capture_mode_label"] != "local-import-stdin" || preview["local_hygiene_path"] != true {
		t.Fatalf("unexpected stdin preview metadata: %+v", preview)
	}
}
