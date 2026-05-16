package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestMCPTargetListingAndExecutionStayAgentSafe(t *testing.T) {
	lockMCPSeams(t)
	handle, projectRoot := setupMCPTargetFixture(t)

	listing, err := callTargets(context.Background(), handle, toolCall{
		Name:      "hasp_targets",
		Arguments: map[string]any{"project_root": projectRoot, "session_token": "session-token"},
	})
	if err != nil {
		t.Fatalf("hasp_targets: %v", err)
	}
	listingJSON, err := json.Marshal(listing)
	if err != nil {
		t.Fatalf("marshal target listing: %v", err)
	}
	for _, forbidden := range []string{"abc123secret", "certificate-data", "printf", "command", "<unsafe>"} {
		if strings.Contains(string(listingJSON), forbidden) {
			t.Fatalf("target listing exposed forbidden content %q in %s", forbidden, listingJSON)
		}
	}
	targets, ok := listing["targets"].([]map[string]any)
	if !ok || len(targets) != 2 {
		t.Fatalf("expected two sanitized targets, got %#v", listing["targets"])
	}
	if listing["manifest_hash"] == "" {
		t.Fatalf("expected manifest hash in listing: %+v", listing)
	}
	explain, err := callTargetExplain(context.Background(), toolCall{
		Name: "hasp_target_explain",
		Arguments: map[string]any{
			"project_root": projectRoot,
			"target":       "server.dev",
		},
	})
	if err != nil {
		t.Fatalf("hasp_target_explain: %v", err)
	}
	explainJSON, err := json.Marshal(explain)
	if err != nil {
		t.Fatalf("marshal target explain: %v", err)
	}
	for _, forbidden := range []string{"abc123secret", "printf"} {
		if strings.Contains(string(explainJSON), forbidden) {
			t.Fatalf("target explain exposed forbidden content %q in %s", forbidden, explainJSON)
		}
	}
	if explain["target"] != "server.dev" || explain["has_command"] != true {
		t.Fatalf("unexpected target explain payload: %+v", explain)
	}
	if _, err := callTargetExplain(context.Background(), toolCall{
		Name:      "hasp_target_explain",
		Arguments: map[string]any{"project_root": projectRoot},
	}); err == nil || !strings.Contains(err.Error(), "target is required") {
		t.Fatalf("expected target-required error, got %v", err)
	}

	startTestDaemon(t)
	runResult, err := callExecute(context.Background(), handle, toolCall{
		Name: "hasp_run",
		Arguments: map[string]any{
			"project_root":  projectRoot,
			"target":        "server.dev",
			"grant_project": "window",
			"grant_secret":  "session",
			"command": []any{
				"sh", "-c",
				`printf '%s' "$API_TOKEN"; test "$(pwd -P)" = "$1"`,
				"target-root-check",
				filepath.Join(projectRoot, "apps", "server"),
			},
		},
	})
	if err != nil {
		t.Fatalf("hasp_run target: %v", err)
	}
	if strings.Contains(runResult["stdout"].(string), "abc123secret") {
		t.Fatalf("target run exposed secret value: %+v", runResult)
	}
	if runResult["target"] != "server.dev" || runResult["manifest_hash"] == "" {
		t.Fatalf("target run missing target metadata: %+v", runResult)
	}

	injectResult, err := callExecute(context.Background(), handle, toolCall{
		Name: "hasp_inject",
		Arguments: map[string]any{
			"project_root":  projectRoot,
			"target":        "release.sign",
			"grant_project": "window",
			"grant_secret":  "session",
			"command":       []any{"sh", "-c", `cat "$CERT_PATH"`},
		},
	})
	if err != nil {
		t.Fatalf("hasp_inject target: %v", err)
	}
	if strings.Contains(injectResult["stdout"].(string), "certificate-data") {
		t.Fatalf("target inject exposed file secret value: %+v", injectResult)
	}
	if _, err := callExecute(context.Background(), handle, toolCall{
		Name: "hasp_run",
		Arguments: map[string]any{
			"project_root": projectRoot,
			"target":       "server.dev",
			"env":          map[string]any{"EXTRA": "secret_01"},
			"command":      []any{"true"},
		},
	}); err == nil || !strings.Contains(err.Error(), "target cannot be combined") {
		t.Fatalf("expected additive mapping refusal, got %v", err)
	}
	if _, err := callExecute(context.Background(), handle, toolCall{
		Name: "hasp_run",
		Arguments: map[string]any{
			"project_root": projectRoot,
			"target":       "missing.target",
			"command":      []any{"true"},
		},
	}); err == nil || !strings.Contains(err.Error(), "unknown manifest target") {
		t.Fatalf("expected unknown target error, got %v", err)
	}
}

func TestMCPTargetCoverageEdges(t *testing.T) {
	lockMCPSeams(t)
	handle, projectRoot := setupMCPTargetFixture(t)

	if _, err := callTool(context.Background(), toolCall{Name: "hasp_targets", Arguments: map[string]any{"project_root": projectRoot, "session_token": "session-token"}}); err != nil {
		t.Fatalf("dispatch hasp_targets: %v", err)
	}
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_target_explain", Arguments: map[string]any{"project_root": projectRoot, "target": "release.sign"}}); err != nil {
		t.Fatalf("dispatch hasp_target_explain: %v", err)
	}
	if explain, err := callTargetExplain(context.Background(), toolCall{Arguments: map[string]any{"project_root": projectRoot, "target": "release.sign"}}); err != nil {
		t.Fatalf("explain file target: %v", err)
	} else if kinds, ok := explain["delivery_kinds"].([]string); !ok || len(kinds) != 1 || kinds[0] != store.ManifestDeliveryFile {
		t.Fatalf("unexpected file delivery kinds: %+v", explain)
	}

	writeMCPXCConfigManifestForCoverage(t, projectRoot)
	if explain, err := callTargetExplain(context.Background(), toolCall{Arguments: map[string]any{"project_root": projectRoot, "target": "build.config"}}); err != nil {
		t.Fatalf("explain xcconfig target: %v", err)
	} else if kinds, ok := explain["delivery_kinds"].([]string); !ok || len(kinds) != 1 || kinds[0] != store.ManifestDeliveryXCConfig {
		t.Fatalf("unexpected xcconfig delivery kinds: %+v", explain)
	}
	origEnsure := ensureSessionFn
	t.Cleanup(func() { ensureSessionFn = origEnsure })
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "session-token"}, nil
	}
	if _, err := callExecute(context.Background(), handle, toolCall{
		Name:      "hasp_run",
		Arguments: map[string]any{"project_root": projectRoot, "target": "build.config", "command": []any{"true"}},
	}); err == nil || !strings.Contains(err.Error(), "workspace-visible") {
		t.Fatalf("expected workspace-output refusal, got %v", err)
	}

	origCanonical := canonicalProjectRootMCPFn
	t.Cleanup(func() { canonicalProjectRootMCPFn = origCanonical })
	canonicalProjectRootMCPFn = func(context.Context, string) (string, error) { return "", errors.New("canonical fail") }
	if _, err := callTargets(context.Background(), handle, toolCall{Arguments: map[string]any{"project_root": projectRoot, "session_token": "session-token"}}); err == nil {
		t.Fatal("expected target listing canonical error")
	}
	if _, err := callTargetExplain(context.Background(), toolCall{Arguments: map[string]any{"project_root": projectRoot, "target": "server.dev"}}); err == nil {
		t.Fatal("expected target explain canonical error")
	}
	if _, err := callExecute(context.Background(), handle, toolCall{
		Name:      "hasp_run",
		Arguments: map[string]any{"project_root": projectRoot, "target": "server.dev", "command": []any{"true"}},
	}); err == nil {
		t.Fatal("expected target execute canonical error")
	}
	canonicalProjectRootMCPFn = origCanonical
	if _, err := callTargets(context.Background(), handle, toolCall{Arguments: map[string]any{"project_root": t.TempDir(), "session_token": "session-token"}}); err == nil {
		t.Fatal("expected missing manifest error")
	}
	if _, err := callTargetExplain(context.Background(), toolCall{Arguments: map[string]any{"project_root": projectRoot, "target": "missing"}}); err == nil {
		t.Fatal("expected target explain expansion error")
	}
	if got := sanitizeMCPDescription(" <bad>\n" + strings.Repeat("x", 300)); strings.ContainsAny(got, "<>\n") || len(got) != 240 {
		t.Fatalf("sanitized description = %q len=%d", got, len(got))
	}
	if uniqueStrings(nil) != nil {
		t.Fatal("empty uniqueStrings should return nil")
	}
	if got := uniqueStrings([]string{"b", "a", "a", "b"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("uniqueStrings = %+v", got)
	}
}

func writeMCPXCConfigManifestForCoverage(t *testing.T, projectRoot string) {
	t.Helper()
	manifest := `{
  "version": "v1",
  "references": [{"alias": "config_01", "item": "api_token"}],
  "requirements": [{"ref": "config_01", "kind": "kv", "classification": "public_config", "required": true}],
  "targets": [
    {
      "name": "build.config",
      "root": ".",
      "delivery": [{"as": "xcconfig", "name": "API_TOKEN", "ref": "config_01", "output": "Config/Secrets.generated.xcconfig"}]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(projectRoot, ".hasp.manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("write xcconfig manifest: %v", err)
	}
}

func setupMCPTargetFixture(t *testing.T) (*store.Handle, string) {
	t.Helper()

	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))
	t.Setenv("HASP_MASTER_PASSWORD", "secret-password")

	vaultStore, err := store.New(store.NewDefaultKeyring())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "secret-password"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "secret-password")
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	projectRoot := filepath.Join(baseDir, "project")
	if err := os.MkdirAll(filepath.Join(projectRoot, "apps", "server"), 0o755); err != nil {
		t.Fatalf("mkdir server root: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123secret"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		t.Fatalf("upsert api token: %v", err)
	}
	if _, err := handle.UpsertItem("cert_file", store.ItemKindFile, []byte("certificate-data"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		t.Fatalf("upsert cert file: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{
		"secret_01": "api_token",
		"file_01":   "cert_file",
	}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	grantMCPProjectSession(t, handle, projectRoot, "session-token")
	manifest := `{
  "version": "v1",
  "references": [
    {"alias": "secret_01", "item": "api_token"},
    {"alias": "file_01", "item": "cert_file"}
  ],
  "requirements": [
    {"ref": "secret_01", "kind": "kv", "classification": "secret", "required": true},
    {"ref": "file_01", "kind": "file", "classification": "secret", "required": true}
  ],
  "targets": [
    {
      "name": "server.dev",
      "description": "Server target with <unsafe> markup",
      "root": "apps/server",
      "command": ["sh", "-c", "printf '%s' \"$API_TOKEN\""],
      "delivery": [{"as": "env", "name": "API_TOKEN", "ref": "secret_01"}]
    },
    {
      "name": "release.sign",
      "root": ".",
      "delivery": [{"as": "file", "name": "CERT_PATH", "ref": "file_01"}]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(projectRoot, ".hasp.manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return handle, projectRoot
}
