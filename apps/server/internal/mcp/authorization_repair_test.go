package mcp

import "testing"

func TestMCPAuthorizationErrorsGiveReplayableRepair(t *testing.T) {
	lockMCPSeams(t)
	_, root := setupMCPTargetFixture(t)
	t.Setenv(mcpEnvSessionToken, "")
	startTestDaemon(t)
	client := newMCPProtocolClient(t)
	args := map[string]any{"project_root": root, "env": map[string]string{"TOKEN": "@api_token"}, "command": []string{"sh", "-c", "test -n \"$TOKEN\""}}
	for _, field := range []string{"grant_project", "grant_secret"} {
		response := client.call("hasp_run", args)
		failure, ok := response["error"].(map[string]any)
		if !ok {
			t.Fatalf("expected authorization failure: %+v", response)
		}
		data, ok := failure["data"].(map[string]any)
		if !ok || data["grant_field"] != field || data["once_consumed"] != false {
			t.Fatalf("missing precise, replayable %s repair: %+v", field, failure)
		}
		args[field] = "once"
	}
	assertMCPSuccessfulRun(t, client.call("hasp_run", args))
	response := client.call("hasp_run", args)
	failure := response["error"].(map[string]any)
	data, ok := failure["data"].(map[string]any)
	if !ok || data["once_consumed"] != true || data["reason"] != "project_lease_required" {
		t.Fatalf("consumed once grant was not identified: %+v", failure)
	}
	assertMCPSuccessfulRun(t, newMCPProtocolClient(t).call("hasp_run", args))
}
