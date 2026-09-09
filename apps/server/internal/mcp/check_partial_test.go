package mcp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMCPCheckStagedAndPartialResults(t *testing.T) {
	lockMCPSeams(t)
	_, root := setupMCPTargetFixture(t)
	t.Setenv(mcpEnvSessionToken, "")
	mustGit(t, root, "init")
	path := filepath.Join(root, "token")
	if err := os.WriteFile(path, []byte("abc123secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustGit(t, root, "add", "token")
	if err := os.WriteFile(path, []byte("cleaned"), 0o600); err != nil {
		t.Fatal(err)
	}
	startTestDaemon(t)
	client := newMCPProtocolClient(t)
	assertMCPFailure(t, client.call("hasp_check", map[string]any{"project_root": root, "staged": true}), "project_lease_required")
	staged := mustMCPToolPayload(t, client.call("hasp_check", map[string]any{"project_root": root, "staged": true, "grant_project": "session"}))
	if staged["walker"] != "git-staged" || staged["complete"] != true || len(staged["matches"].([]any)) != 1 {
		t.Fatalf("staged scan missed index content: %+v", staged)
	}
	stats, ok := staged["stats"].(map[string]any)
	if !ok || stats["sources_scanned"] != float64(1) || stats["bytes_scanned"] != float64(len("abc123secret")) || stats["total_ms"].(float64) <= 0 {
		t.Fatalf("staged scan omitted measurements: %+v", staged)
	}
	working := mustMCPToolPayload(t, client.call("hasp_check", map[string]any{"project_root": root}))
	if working["matches"] != nil || working["complete"] != true {
		t.Fatalf("working scan read the index: %+v", working)
	}
	if os.Geteuid() == 0 {
		t.Skip("unreadable-file replay requires a non-root user")
	}
	if err := os.WriteFile(filepath.Join(root, "a-leak"), []byte("abc123secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(root, "b-unreadable")
	if err := os.WriteFile(blocked, []byte("content"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o600) })
	response := client.call("hasp_check", map[string]any{"project_root": root})
	result, ok := response["result"].(map[string]any)
	if !ok || result["isError"] != true {
		t.Fatalf("I/O failure not marked as tool error: %+v", response)
	}
	payload := result["structuredContent"].(map[string]any)
	if payload["complete"] != false || len(payload["matches"].([]any)) != 1 || len(payload["issues"].([]any)) != 1 {
		t.Fatalf("partial result lost matches or coverage: %+v", payload)
	}
	if payload["error"].(map[string]any)["code"] != "E_SCAN_INCOMPLETE" {
		t.Fatalf("wrong scan error: %+v", payload)
	}
}
