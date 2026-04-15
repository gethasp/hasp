//go:build integration

package evals

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestMCPEndToEndEval(t *testing.T) {
	env := newEvalEnv(t)
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(certPath, []byte("certificate-data"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if _, _, err := runHasp(t, env, "", "init"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	if _, _, err := runHasp(t, env, "", "set", "--name", "api_token", "--value", "abc123"); err != nil {
		t.Fatalf("set api_token failed: %v", err)
	}
	if _, _, err := runHasp(t, env, "", "set", "--name", "cert_file", "--kind", "file", "--from-file", certPath); err != nil {
		t.Fatalf("set cert_file failed: %v", err)
	}
	if _, _, err := runHasp(t, env, "", "project", "bind", "--project-root", env.projectRoot, "--alias", "secret_01=api_token", "--alias", "file_01=cert_file"); err != nil {
		t.Fatalf("project bind failed: %v", err)
	}

	sessionToken := openRuntimeSession(t, env, env.projectRoot, int(runtime.DefaultSessionTTL.Seconds()))
	responses, err := runMCPBinaryRequests(t, env, []map[string]any{
		{"jsonrpc": "2.0", "id": 1, "method": "initialize"},
		{"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
		{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{
			"name": "hasp_list",
			"arguments": map[string]any{
				"project_root":  env.projectRoot,
				"session_token": sessionToken,
				"grant_project": "window",
			},
		}},
		{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{
			"name": "hasp_run",
			"arguments": map[string]any{
				"project_root":  env.projectRoot,
				"session_token": sessionToken,
				"grant_secret":  "session",
				"env":           map[string]any{"API_TOKEN": "secret_01"},
				"command":       []any{"sh", "-c", "printf '%s' \"$API_TOKEN\""},
			},
		}},
		{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": map[string]any{
			"name": "hasp_inject",
			"arguments": map[string]any{
				"project_root":  env.projectRoot,
				"session_token": sessionToken,
				"grant_secret":  "session",
				"files":         map[string]any{"CERT_PATH": "file_01"},
				"command":       []any{"sh", "-c", "cat \"$CERT_PATH\""},
			},
		}},
		{"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": map[string]any{
			"name": "hasp_capture",
			"arguments": map[string]any{
				"project_root":  env.projectRoot,
				"session_token": sessionToken,
				"grant_project": "window",
				"grant_write":   true,
				"name":          "generated_token",
				"value":         "xyz789",
			},
		}},
		{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{
			"name":      "hasp_redact",
			"arguments": map[string]any{"text": "token=abc123"},
		}},
	})
	if err != nil {
		t.Fatalf("run mcp requests: %v", err)
	}

	if !strings.Contains(mustJSON(t, responses[0]), "protocolVersion") {
		t.Fatalf("initialize response malformed: %s", mustJSON(t, responses[0]))
	}
	listResult := responses[2]["result"].(map[string]any)
	if _, ok := listResult["visible"]; !ok {
		t.Fatalf("hasp_list missing visible result: %v", listResult)
	}
	runResult := responses[3]["result"].(map[string]any)
	if strings.Contains(runResult["stdout"].(string), "abc123") {
		t.Fatalf("mcp run leaked secret: %v", runResult)
	}
	injectResult := responses[4]["result"].(map[string]any)
	if strings.Contains(injectResult["stdout"].(string), "certificate-data") {
		t.Fatalf("mcp inject leaked file content: %v", injectResult)
	}
	captureResult := responses[5]["result"].(map[string]any)
	if captureResult["item_name"] != "generated_token" {
		t.Fatalf("unexpected capture result: %v", captureResult)
	}
	redactResult := responses[6]["result"].(map[string]any)
	if strings.Contains(redactResult["text"].(string), "abc123") {
		t.Fatalf("mcp redact leaked value: %v", redactResult)
	}

	leakPath := filepath.Join(env.projectRoot, "leak.txt")
	if err := os.WriteFile(leakPath, []byte("abc123"), 0o600); err != nil {
		t.Fatalf("write leak: %v", err)
	}
	checkResponses, err := runMCPBinaryRequests(t, env, []map[string]any{
		{"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": map[string]any{
			"name":      "hasp_check",
			"arguments": map[string]any{"project_root": env.projectRoot},
		}},
	})
	if err != nil {
		t.Fatalf("mcp check failed: %v", err)
	}
	if !strings.Contains(mustJSON(t, checkResponses[0]), "leak.txt") {
		t.Fatalf("hasp_check missed leak file: %s", mustJSON(t, checkResponses[0]))
	}
}

func TestMCPFailureEval(t *testing.T) {
	env := newEvalEnv(t)
	if _, _, err := runHasp(t, env, "", "init"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	if _, _, err := runHasp(t, env, "", "set", "--name", "api_token", "--value", "abc123"); err != nil {
		t.Fatalf("set failed: %v", err)
	}
	if _, _, err := runHasp(t, env, "", "project", "bind", "--project-root", env.projectRoot, "--alias", "secret_01=api_token"); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	token := openRuntimeSession(t, env, env.projectRoot, int(runtime.DefaultSessionTTL.Seconds()))
	revokeRuntimeSession(t, env, token)
	if _, err := runMCPBinaryRequests(t, env, []map[string]any{
		{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{
			"name": "hasp_run",
			"arguments": map[string]any{
				"project_root":  env.projectRoot,
				"session_token": token,
				"env":           map[string]any{"API_TOKEN": "secret_01"},
				"command":       []any{"true"},
			},
		}},
	}); err == nil {
		t.Fatal("mcp run unexpectedly succeeded with revoked token")
	}

	expiredToken := openRuntimeSession(t, env, env.projectRoot, 1)
	time.Sleep(2 * time.Second)
	if _, err := runMCPBinaryRequests(t, env, []map[string]any{
		{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{
			"name": "hasp_list",
			"arguments": map[string]any{
				"project_root":  env.projectRoot,
				"session_token": expiredToken,
			},
		}},
	}); err == nil {
		t.Fatal("mcp list unexpectedly succeeded with expired token")
	}

	_, _, err := runCmdWithInput(t, env.projectRoot, env.commandEnv(nil), "{bad json\n", env.binary, "mcp")
	if err == nil {
		t.Fatal("mcp malformed input unexpectedly succeeded")
	}
}

func runMCPBinaryRequests(t *testing.T, env evalEnv, requests []map[string]any) ([]map[string]any, error) {
	t.Helper()
	var input bytes.Buffer
	enc := json.NewEncoder(&input)
	for _, req := range requests {
		if err := enc.Encode(req); err != nil {
			return nil, err
		}
	}
	stdout, stderr, err := runCmdWithInput(t, env.projectRoot, env.commandEnv(nil), input.String(), env.binary, "mcp")
	if err != nil {
		return nil, fmt.Errorf("mcp exec: %w stderr=%s", err, stderr)
	}
	dec := json.NewDecoder(strings.NewReader(stdout))
	responses := make([]map[string]any, 0, len(requests))
	for range requests {
		var resp map[string]any
		if err := dec.Decode(&resp); err != nil {
			return nil, err
		}
		if rawErr, ok := resp["error"]; ok && rawErr != nil {
			return nil, errors.New(rawErr.(map[string]any)["message"].(string))
		}
		responses = append(responses, resp)
	}
	return responses, nil
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}
	return string(data)
}
