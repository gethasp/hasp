package mcp

import (
	"path/filepath"
	"testing"
)

func TestStatusReportsTransportWithoutVaultOrAuthorization(t *testing.T) {
	lockMCPSeams(t)
	t.Setenv("HASP_HOME", filepath.Join(t.TempDir(), "uninitialized"))
	t.Setenv("HASP_MASTER_PASSWORD", "")
	t.Setenv("HASP_SESSION_TOKEN", "")
	responses := exchangeMCPRequests(t, []map[string]any{{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "hasp_status", "arguments": map[string]any{}},
	}})
	payload := mustMCPToolPayload(t, responses[0])
	if payload["connection"] != "connected" || payload["authorization"] != "not_checked" || payload["client_shell_protection"] != "not_attested" {
		t.Fatalf("status claims more than the transport: %+v", payload)
	}
}
