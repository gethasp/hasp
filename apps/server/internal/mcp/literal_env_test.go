package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMCPLiteralEnvMixedDeliveryAndFailureBeforeOnceConsumption(t *testing.T) {
	lockMCPSeams(t)
	_, root := setupMCPTargetFixture(t)
	t.Setenv(mcpEnvSessionToken, "")
	startTestDaemon(t)
	client := newMCPProtocolClient(t)
	args := map[string]any{"project_root": root, "env": map[string]string{"TOKEN": "@api_token"}, "files": map[string]string{"CERT": "@cert_file"}, "literal_env": map[string]string{"CI": "1", "EMPTY": "", "EXACT": " @TOKEN=$HOME=a=b "}, "grant_project": "once", "grant_secret": "once", "command": []string{"sh", "-c", `test "$CI" = 1 && test "${EMPTY+x}" = x && test -z "$EMPTY" && test "$EXACT" = ' @TOKEN=$HOME=a=b ' && test -n "$TOKEN" && test -f "$CERT" && cat "$CERT" && printf '%s' "$TOKEN"`}}
	for _, invalid := range []any{map[string]any{"CI": 1}, "CI=1", nil, map[string]string{"TOKEN": "1"}, map[string]string{"HASP_AGENT_SAFE_MODE": "0"}} {
		args["literal_env"] = invalid
		response := client.call("hasp_run", args)
		if response["error"] == nil {
			t.Fatalf("accepted invalid literal map: %+v", response)
		}
	}
	args["literal_env"] = map[string]string{"CI": "1", "EMPTY": "", "EXACT": " @TOKEN=$HOME=a=b "}
	payload := mustMCPToolPayload(t, client.call("hasp_run", args))
	if payload["exit_code"] != float64(0) || payload["redacted"] != true {
		t.Fatalf("mixed delivery failed: %+v", payload)
	}
	data, _ := json.Marshal(payload)
	if strings.Contains(string(data), "abc123secret") || strings.Contains(string(data), "certificate-data") {
		t.Fatal("managed content was not redacted")
	}
	if response := client.call("hasp_run", args); response["error"] == nil {
		t.Fatal("once grant replayed")
	}
	// Schema advertises both reference maps and literal configuration for all execution tools.
	for _, tool := range catalog() {
		if tool.Name != "hasp_run" && tool.Name != "hasp_inject" && tool.Name != "hasp_job_start" {
			continue
		}
		properties := tool.InputSchema["properties"].(map[string]any)
		for _, name := range []string{"env", "files", "literal_env"} {
			if properties[name] == nil {
				t.Fatalf("%s hides %s", tool.Name, name)
			}
		}
	}
}

func TestJobFingerprintIncludesExactLiteralValues(t *testing.T) {
	fingerprint := func(value string) string {
		return jobFingerprint([]string{"true"}, nil, nil, map[string]string{"CI": value}, "/repo", "")
	}
	if fingerprint("1") == fingerprint("2") || fingerprint("1") == fingerprint(" 1 ") {
		t.Fatal("literal value change reused job fingerprint")
	}
}
