package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/auditlog"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func BenchmarkToolsList(b *testing.B) {
	var input bytes.Buffer
	enc := json.NewEncoder(&input)
	if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}); err != nil {
		b.Fatalf("encode request: %v", err)
	}
	requestBody := input.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		if err := Serve(context.Background(), bytes.NewBufferString(requestBody), &out); err != nil {
			b.Fatalf("serve tools/list: %v", err)
		}
	}
}

func BenchmarkHaspRunTool(b *testing.B) {
	state := setupBenchmarkMCPState(b)
	request := request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: mustMarshal(b, toolCall{
			Name: "hasp_run",
			Arguments: map[string]any{
				"project_root":  state.projectRoot,
				"grant_project": "window",
				"grant_secret":  "session",
				"env":           map[string]any{"API_TOKEN": "secret_01"},
				"command":       []any{"true"},
			},
		}),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := callTool(context.Background(), mustCall(b, request)); err != nil {
			b.Fatalf("call tool: %v", err)
		}
	}
}

func BenchmarkHaspListTool(b *testing.B) {
	state := setupBenchmarkMCPState(b)
	request := request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: mustMarshal(b, toolCall{
			Name: "hasp_list",
			Arguments: map[string]any{
				"project_root":  state.projectRoot,
				"grant_project": "window",
			},
		}),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := callTool(context.Background(), mustCall(b, request)); err != nil {
			b.Fatalf("call tool: %v", err)
		}
	}
}

func BenchmarkHaspInjectTool(b *testing.B) {
	state := setupBenchmarkMCPState(b)
	request := request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: mustMarshal(b, toolCall{
			Name: "hasp_inject",
			Arguments: map[string]any{
				"project_root":  state.projectRoot,
				"grant_project": "window",
				"grant_secret":  "session",
				"files":         map[string]any{"CERT_PATH": "file_01"},
				"command":       []any{"true"},
			},
		}),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := callTool(context.Background(), mustCall(b, request)); err != nil {
			b.Fatalf("call tool: %v", err)
		}
	}
}

func BenchmarkHaspCheckTool(b *testing.B) {
	state := setupBenchmarkMCPState(b)
	projectRoot := state.projectRoot
	for i := 0; i < 100; i++ {
		path := filepath.Join(projectRoot, fmt.Sprintf("file-%03d.txt", i))
		if err := os.WriteFile(path, []byte("safe content"), 0o600); err != nil {
			b.Fatalf("write repo file: %v", err)
		}
	}
	request := request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: mustMarshal(b, toolCall{
			Name: "hasp_check",
			Arguments: map[string]any{
				"project_root":  projectRoot,
				"session_token": state.sessionToken,
				"grant_project": "window",
			},
		}),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := callTool(context.Background(), mustCall(b, request)); err != nil {
			b.Fatalf("call tool: %v", err)
		}
	}
}

func mustMarshal(b *testing.B, value any) json.RawMessage {
	b.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		b.Fatalf("marshal value: %v", err)
	}
	return data
}

func mustCall(b *testing.B, req request) toolCall {
	b.Helper()
	var call toolCall
	if err := json.Unmarshal(req.Params, &call); err != nil {
		b.Fatalf("unmarshal tool call: %v", err)
	}
	return call
}

type benchmarkMCPState struct {
	projectRoot  string
	sessionToken string
}

func setupBenchmarkMCPState(b *testing.B) benchmarkMCPState {
	b.Helper()
	baseDir := b.TempDir()
	b.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))
	socketDir, err := os.MkdirTemp("/tmp", "hasp-bench-")
	if err != nil {
		b.Fatalf("create benchmark socket dir: %v", err)
	}
	b.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	b.Setenv(paths.EnvSocket, filepath.Join(socketDir, "s.sock"))
	b.Setenv("HASP_MASTER_PASSWORD", "secret-password")

	vaultStore, err := store.New(store.NewDefaultKeyring())
	if err != nil {
		b.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "secret-password"); err != nil {
		b.Fatalf("init vault: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "secret-password")
	if err != nil {
		b.Fatalf("open handle: %v", err)
	}
	auditlog.SetHMACKey(handle.AuditHMACKey())
	auditlog.EnsureKeyedChainSeed()
	b.Cleanup(auditlog.ClearHMACKey)
	projectRoot := filepath.Join(baseDir, "project")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		b.Fatalf("mkdir project: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		b.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertItem("cert_file", store.ItemKindFile, []byte("certificate-data"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		b.Fatalf("upsert file item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token", "file_01": "cert_file"}, store.PolicySession, false); err != nil {
		b.Fatalf("upsert binding: %v", err)
	}
	manager := startBenchmarkDaemon(b)
	client, err := runtime.Dial(context.Background(), manager.SocketPath())
	if err != nil {
		b.Fatalf("dial runtime: %v", err)
	}
	defer client.Close()
	sessionReply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "bench",
		ProjectRoot:  projectRoot,
		TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
		AuditHMACKey: auditlog.GetHMACKey(),
	})
	if err != nil {
		b.Fatalf("open session: %v", err)
	}
	binding, _, err := handle.ResolveBindingView(context.Background(), projectRoot)
	if err != nil {
		b.Fatalf("resolve binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, sessionReply.SessionToken, store.GrantWindow, time.Minute); err != nil {
		b.Fatalf("grant project lease: %v", err)
	}
	if _, err := handle.GrantSecretUse(binding.ID, sessionReply.SessionToken, "api_token", store.GrantSession, 0, false); err != nil {
		b.Fatalf("grant secret use: %v", err)
	}
	if _, err := handle.GrantSecretUse(binding.ID, sessionReply.SessionToken, "cert_file", store.GrantSession, 0, false); err != nil {
		b.Fatalf("grant file secret use: %v", err)
	}
	return benchmarkMCPState{projectRoot: projectRoot, sessionToken: sessionReply.SessionToken}
}

func startBenchmarkDaemon(b *testing.B) *runtime.Manager {
	b.Helper()
	manager, err := runtime.NewManager()
	if err != nil {
		b.Fatalf("new manager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.RunDaemon(ctx)
	}()
	waitForBenchmarkSocket(b, manager.SocketPath(), errCh)
	b.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				b.Fatalf("daemon exited: %v", err)
			}
		case <-time.After(10 * time.Second):
			// CI coverage runs leave daemon shutdown contended; widen this
			// safety cap so a slow scheduler tick doesn't fail the benchmark.
			b.Fatal("timed out waiting for benchmark daemon shutdown")
		}
	})
	return manager
}

func waitForBenchmarkSocket(b *testing.B, socketPath string, errCh <-chan error) {
	b.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			if err != nil {
				b.Fatalf("daemon startup failed: %v", err)
			}
			b.Fatal("daemon exited before socket became available")
		default:
		}
		client, err := runtime.Dial(context.Background(), socketPath)
		if err == nil {
			client.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	b.Fatalf("timed out waiting for socket %s", socketPath)
}
