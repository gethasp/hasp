package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestTargetsFreshClientCanRepairUsingAdvertisedSchema(t *testing.T) {
	lockMCPSeams(t)
	_, root := setupMCPTargetFixture(t)
	t.Setenv("HASP_SESSION_TOKEN", "")
	startTestDaemon(t)

	requests := []map[string]any{{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}}
	for i, grant := range []string{"", "once", ""} {
		args := map[string]any{"project_root": root}
		if grant != "" {
			args["grant_project"] = grant
		}
		requests = append(requests, map[string]any{
			"jsonrpc": "2.0", "id": i + 2, "method": "tools/call",
			"params": map[string]any{"name": "hasp_targets", "arguments": args},
		})
	}
	responses := exchangeMCPRequests(t, requests)
	listed := responses[0]["result"].(map[string]any)["tools"].([]any)
	var properties map[string]any
	for _, raw := range listed {
		entry := raw.(map[string]any)
		if entry["name"] == "hasp_targets" {
			properties = entry["inputSchema"].(map[string]any)["properties"].(map[string]any)
		}
	}
	for _, field := range []string{"project_root", "session_token", "host_label", "grant_project"} {
		if _, ok := properties[field]; !ok {
			t.Fatalf("fresh client cannot express target authorization field %q", field)
		}
	}
	for _, index := range []int{1, 3} {
		failure, _ := responses[index]["error"].(map[string]any)
		message, _ := failure["message"].(string)
		if !strings.Contains(message, "project_lease_required") {
			t.Fatalf("call %d must require a project lease: %+v", index, responses[index])
		}
	}
	payload := mustMCPToolPayload(t, responses[2])
	if targets, _ := payload["targets"].([]any); len(targets) != 2 {
		t.Fatalf("inline once grant did not discover fixture targets: %+v", payload)
	}
}

// exchangeMCPRequests keeps protocol failures so recovery tests can replay the
// complete exchange, including a denied call and its repair, on one connection.
func exchangeMCPRequests(t *testing.T, requests []map[string]any) []map[string]any {
	t.Helper()
	var input, output bytes.Buffer
	encoder := json.NewEncoder(&input)
	for _, req := range requests {
		if err := encoder.Encode(req); err != nil {
			t.Fatal(err)
		}
	}
	if err := Serve(context.Background(), &input, &output); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	responses := make([]map[string]any, len(requests))
	for i := range responses {
		if err := decoder.Decode(&responses[i]); err != nil {
			t.Fatal(err)
		}
	}
	return responses
}
