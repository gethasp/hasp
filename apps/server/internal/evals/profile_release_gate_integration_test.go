//go:build integration

package evals

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/profiles"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestProfileReleaseGateEval(t *testing.T) {
	profilesList, err := profiles.LoadCatalog()
	if err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	for _, profile := range profilesList {
		env := newEvalEnv(t)
		if _, _, err := runHasp(t, env, "", "bootstrap", "--profile", profile.ID, "--project-root", env.projectRoot, "--hooks=false", "--verify=true"); err != nil {
			t.Fatalf("bootstrap %s failed: %v", profile.ID, err)
		}
		if _, _, err := runHasp(t, env, "", "set", "--name", "api_token", "--value", "abc123"); err != nil {
			t.Fatalf("set api token for %s: %v", profile.ID, err)
		}
		certPath := filepath.Join(t.TempDir(), "cert.pem")
		if err := os.WriteFile(certPath, []byte("certificate-data"), 0o600); err != nil {
			t.Fatalf("write cert fixture for %s: %v", profile.ID, err)
		}
		if _, _, err := runHasp(t, env, "", "set", "--name", "cert_file", "--kind", "file", "--from-file", certPath); err != nil {
			t.Fatalf("set cert file for %s: %v", profile.ID, err)
		}
		if _, _, err := runHasp(t, env, "", "bootstrap", "--profile", profile.ID, "--project-root", env.projectRoot, "--hooks=false", "--bind-item", "api_token", "--bind-item", "cert_file", "--verify=false"); err != nil {
			t.Fatalf("bind items for %s: %v", profile.ID, err)
		}

		stdout, _, err := runHasp(t, env, "", "bootstrap", "--profile", profile.ID, "--project-root", env.projectRoot, "--hooks=false", "--verify=true")
		if err != nil {
			t.Fatalf("bootstrap verify %s failed: %v", profile.ID, err)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatalf("decode bootstrap output for %s: %v", profile.ID, err)
		}
		verification, ok := payload["verification"].(map[string]any)
		if !ok || verification["ready"] != true {
			t.Fatalf("expected verified bootstrap for %s: %v", profile.ID, payload)
		}
		if !strings.Contains(stdout, profile.ID) {
			t.Fatalf("expected profile id in bootstrap output for %s: %s", profile.ID, stdout)
		}

		fixture, err := profiles.LoadRegressionFixture(profile)
		if err != nil {
			t.Fatalf("load fixture for %s: %v", profile.ID, err)
		}
		sessionToken := ""
		if fixture.SessionToken != "" {
			sessionToken = openRuntimeSession(t, env, env.projectRoot, int(runtime.DefaultSessionTTL.Seconds()))
		}
		request := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name": fixture.Tool,
				"arguments": map[string]any{
					"project_root": env.projectRoot,
				},
			},
		}
		args := request["params"].(map[string]any)["arguments"].(map[string]any)
		if sessionToken != "" {
			args["session_token"] = sessionToken
		}
		if fixture.GrantProject != "" {
			args["grant_project"] = fixture.GrantProject
		}
		if fixture.GrantSecret != "" {
			args["grant_secret"] = fixture.GrantSecret
		}
		if len(fixture.Env) > 0 {
			envMap := map[string]any{}
			for key, value := range fixture.Env {
				envMap[key] = value
			}
			args["env"] = envMap
		}
		if len(fixture.Files) > 0 {
			fileMap := map[string]any{}
			for key, value := range fixture.Files {
				fileMap[key] = value
			}
			args["files"] = fileMap
		}
		if len(fixture.Command) > 0 {
			command := make([]any, 0, len(fixture.Command))
			for _, part := range fixture.Command {
				command = append(command, part)
			}
			args["command"] = command
		}

		responses, err := runMCPBinaryRequests(t, env, []map[string]any{
			{"jsonrpc": "2.0", "id": 0, "method": "initialize"},
			request,
		})
		if err != nil {
			t.Fatalf("fixture request for %s failed: %v", profile.ID, err)
		}
		if len(responses) != 2 {
			t.Fatalf("expected initialize + tool response for %s, got %d", profile.ID, len(responses))
		}
		toolResponse, ok := responses[1]["result"].(map[string]any)
		if !ok {
			t.Fatalf("missing tool result for %s: %v", profile.ID, responses[1])
		}
		if stdoutValue, ok := toolResponse["stdout"].(string); ok {
			if strings.Contains(stdoutValue, "abc123") || strings.Contains(stdoutValue, "certificate-data") {
				t.Fatalf("fixture path leaked managed values for %s: %v", profile.ID, toolResponse)
			}
		}
	}
}
