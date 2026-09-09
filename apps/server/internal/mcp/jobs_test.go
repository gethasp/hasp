package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMCPJobRecoversLostStartResponseWithoutReplay(t *testing.T) {
	lockMCPSeams(t)
	_, root := setupMCPTargetFixture(t)
	t.Setenv(mcpEnvSessionToken, "")
	_, restart := startRestartableMCPDaemon(t)
	requestID := "9a04f79e22db4d1588bc3d414b63e131"
	args := map[string]any{"project_root": root, "request_id": requestID, "grant_project": "once", "grant_secret": "once",
		"literal_env": map[string]string{"CI": "1"},
		"env":         map[string]string{"TOKEN": "@api_token"}, "files": map[string]string{"CERT": "@cert_file"},
		"command": []string{"sh", "-c", `test "$CI" = 1 || exit 9; printf x >> executions; test -f "$CERT" || exit 8; printf '%s\n' "$TOKEN"; printf '%02000d\n' 0; while [ ! -e release ]; do sleep 0.02; done; printf 'finished\n'; exit 7`}}
	// Expire the client's response deadline, then lose its MCP connection.
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { defer server.Close(); done <- Serve(context.Background(), server, server) }()
	if err := json.NewEncoder(client).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "hasp_job_start", "arguments": args}}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	var lostResponse any
	var timeout net.Error
	if err := json.NewDecoder(client).Decode(&lostResponse); !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("expected a client response timeout, got %v", err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("MCP waited for the child instead of returning a job handle")
	}
	reconnected := newMCPProtocolClient(t)
	query := map[string]any{"project_root": root, "request_id": requestID}
	progress := pollMCPJob(t, reconnected, query, func(status map[string]any) bool { return strings.Contains(status["stdout"].(string), "[REDACTED") })
	if progress["state"] != "running" || strings.Contains(progress["stdout"].(string), "abc123secret") {
		t.Fatalf("expected live redacted progress: %+v", progress)
	}
	assertMCPFailure(t, reconnected.call("hasp_targets", map[string]any{"project_root": root}), "project_lease_required")
	duplicate := mustMCPToolPayload(t, reconnected.call("hasp_job_start", args))
	if duplicate["job_id"] != progress["job_id"] {
		t.Fatal("retry did not return original job")
	}
	args["literal_env"] = map[string]string{"CI": " 1 "}
	assertMCPFailure(t, reconnected.call("hasp_job_start", args), "different command")
	args["literal_env"] = map[string]string{"CI": "1"}
	args["command"] = []string{"true"}
	assertMCPFailure(t, reconnected.call("hasp_job_start", args), "different command")
	other := t.TempDir()
	assertMCPFailure(t, reconnected.call("hasp_job_status", map[string]any{"project_root": other, "job_id": progress["job_id"]}), "different project")
	if err := os.WriteFile(filepath.Join(root, "release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	query["stdout_offset"] = progress["stdout_offset"]
	final := pollMCPJob(t, reconnected, query, func(status map[string]any) bool { return status["state"] == "completed" })
	if final["exit_code"] != float64(7) || !strings.Contains(final["stdout"].(string), "finished") {
		t.Fatalf("lost final exit/progress: %+v", final)
	}
	restart()
	final = mustMCPToolPayload(t, newMCPProtocolClient(t).call("hasp_job_status", query))
	if final["state"] != "completed" || final["exit_code"] != float64(7) {
		t.Fatalf("final receipt did not survive daemon restart: %+v", final)
	}
	marker, err := os.ReadFile(filepath.Join(root, "executions"))
	if err != nil || string(marker) != "x" {
		t.Fatalf("job executed more than once: %q, %v", marker, err)
	}
}

func TestMCPJobCancelCleansInjectedFilesAndDoesNotReplay(t *testing.T) {
	lockMCPSeams(t)
	_, root := setupMCPTargetFixture(t)
	t.Setenv(mcpEnvSessionToken, "")
	startTestDaemon(t)
	client := newMCPProtocolClient(t)
	args := map[string]any{"project_root": root, "request_id": "0837c13dde0b4e90b2f7c450e0f46c12", "grant_project": "once", "grant_secret": "once",
		"files": map[string]string{"CERT": "@cert_file"}, "command": []string{"sh", "-c", `printf '%s' "$CERT" > injected-path; (sleep 2; touch orphan-ran) & wait`}}
	first := mustMCPToolPayload(t, client.call("hasp_job_start", args))
	deadline := time.Now().Add(5 * time.Second)
	var path []byte
	for time.Now().Before(deadline) {
		path, _ = os.ReadFile(filepath.Join(root, "injected-path"))
		if len(path) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(path) == 0 {
		t.Fatal("child did not start")
	}
	query := map[string]any{"project_root": root, "job_id": first["job_id"]}
	mustMCPToolPayload(t, client.call("hasp_job_cancel", query))
	pollMCPJob(t, client, query, func(status map[string]any) bool { return status["state"] == "cancelled" })
	if _, err := os.Stat(string(path)); !os.IsNotExist(err) {
		t.Fatalf("injected file survived cancellation: %v", err)
	}
	retry := mustMCPToolPayload(t, client.call("hasp_job_start", args))
	if retry["state"] != "cancelled" {
		t.Fatalf("cancelled request was replayed: %+v", retry)
	}
	time.Sleep(2100 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(root, "orphan-ran")); !os.IsNotExist(err) {
		t.Fatalf("cancel left a running grandchild: %v", err)
	}
}

func pollMCPJob(t *testing.T, client *mcpProtocolClient, query map[string]any, ready func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var status map[string]any
	for time.Now().Before(deadline) {
		status = mustMCPToolPayload(t, client.call("hasp_job_status", query))
		if ready(status) {
			return status
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job did not reach expected state: %+v", status)
	return nil
}
