package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/auditlog"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/reposcan"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestToolsListAndCall(t *testing.T) {
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
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	startTestDaemon(t)

	var input bytes.Buffer
	var output bytes.Buffer
	enc := json.NewEncoder(&input)
	if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}); err != nil {
		t.Fatalf("encode tools/list: %v", err)
	}
	if err := enc.Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "hasp_list",
			"arguments": map[string]any{
				"project_root":  projectRoot,
				"grant_project": "window",
			},
		},
	}); err != nil {
		t.Fatalf("encode tools/call: %v", err)
	}

	if err := Serve(context.Background(), &input, &output); err != nil {
		t.Fatalf("serve mcp: %v", err)
	}

	dec := json.NewDecoder(&output)
	var listResp map[string]any
	if err := dec.Decode(&listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	tools := listResp["result"].(map[string]any)["tools"].([]any)
	var runSchema map[string]any
	for _, rawTool := range tools {
		tool := rawTool.(map[string]any)
		switch tool["name"] {
		case "hasp_run":
			runSchema = tool["inputSchema"].(map[string]any)
		case "hasp_capture", "hasp_secret_add", "hasp_secret_update", "hasp_secret_delete", "hasp_secret_expose", "hasp_secret_hide":
			t.Fatalf("unsafe write/mutation tool %q must not be in the default MCP schema", tool["name"])
		}
	}
	if runSchema == nil {
		t.Fatal("expected run schema")
	}
	runProps := runSchema["properties"].(map[string]any)
	if _, ok := runProps["grant_project"]; !ok {
		t.Fatal("expected hasp_run schema to expose grant_project")
	}
	if _, ok := runProps["grant_secret"]; !ok {
		t.Fatal("expected hasp_run schema to expose grant_secret")
	}
	var callResp map[string]any
	if err := dec.Decode(&callResp); err != nil {
		t.Fatalf("decode call response: %v", err)
	}
	if callResp["error"] != nil {
		t.Fatalf("unexpected tool error: %+v", callResp["error"])
	}
	result := callResp["result"].(map[string]any)
	if _, ok := result["binding"]; ok {
		t.Fatalf("expected safe list response without binding payload")
	}
}

func TestHaspRunAndInjectParity(t *testing.T) {
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
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		t.Fatalf("upsert api_token: %v", err)
	}
	if _, err := handle.UpsertItem("cert_file", store.ItemKindFile, []byte("certificate-data"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		t.Fatalf("upsert cert_file: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{
		"secret_01": "api_token",
		"file_01":   "cert_file",
	}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	startTestDaemon(t)

	responses, err := runMCPRequests([]map[string]any{
		{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name": "hasp_run",
				"arguments": map[string]any{
					"project_root":  projectRoot,
					"grant_project": "window",
					"grant_secret":  "session",
					"env":           map[string]any{"API_TOKEN": "@api_token"},
					"command":       []any{"sh", "-c", "printf '%s' \"$API_TOKEN\""},
				},
			},
		},
		{
			"jsonrpc": "2.0",
			"id":      2,
			"method":  "tools/call",
			"params": map[string]any{
				"name": "hasp_inject",
				"arguments": map[string]any{
					"project_root":  projectRoot,
					"grant_project": "window",
					"grant_secret":  "session",
					"files":         map[string]any{"CERT_PATH": "@cert_file"},
					"command":       []any{"sh", "-c", "cat \"$CERT_PATH\""},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("run mcp requests: %v", err)
	}

	runResult := responses[0]["result"].(map[string]any)
	if strings.Contains(runResult["stdout"].(string), "abc123") {
		t.Fatalf("expected run output to be redacted, got %q", runResult["stdout"])
	}
	injectResult := responses[1]["result"].(map[string]any)
	if strings.Contains(injectResult["stdout"].(string), "certificate-data") {
		t.Fatalf("expected inject output to be redacted, got %q", injectResult["stdout"])
	}
}

func TestHaspCaptureRequiresWriteGrant(t *testing.T) {
	t.Setenv(mcpEnvUnsafeWriteTools, "1")
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
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	startTestDaemon(t)

	_, err = runMCPRequests([]map[string]any{
		{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name": "hasp_capture",
				"arguments": map[string]any{
					"project_root":  projectRoot,
					"grant_project": "window",
					"name":          "api_token",
					"value":         "abc123",
				},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "capture write grant required") {
		t.Fatalf("expected explicit write grant error, got %v", err)
	}
}

func TestHaspCaptureAuditsExplicitWriteGrant(t *testing.T) {
	t.Setenv(mcpEnvUnsafeWriteTools, "1")
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
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	startTestDaemon(t)

	if _, err := runMCPRequests([]map[string]any{
		{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name": "hasp_capture",
				"arguments": map[string]any{
					"project_root":  projectRoot,
					"grant_project": "window",
					"grant_write":   true,
					"name":          "api_token",
					"value":         "abc123",
				},
			},
		},
	}); err != nil {
		t.Fatalf("capture request: %v", err)
	}
	resolvedPaths, err := paths.Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	data, err := os.ReadFile(resolvedPaths.AuditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(data), "capture.write_grant") {
		t.Fatalf("expected capture write-grant audit entry, got %s", string(data))
	}
}

func TestHaspRunRejectsSessionProjectMismatch(t *testing.T) {
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
	projectA := filepath.Join(baseDir, "project-a")
	projectB := filepath.Join(baseDir, "project-b")
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		t.Fatalf("upsert api_token: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectA, map[string]string{"secret_01": "api_token"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectB, map[string]string{"secret_01": "api_token"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	manager := startTestDaemon(t)
	client, err := runtime.Dial(context.Background(), manager.SocketPath())
	if err != nil {
		t.Fatalf("dial runtime: %v", err)
	}
	defer client.Close()
	sessionReply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:   "mcp-test",
		ProjectRoot: projectA,
		TTLSeconds:  int(runtime.DefaultSessionTTL.Seconds()),
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	_, err = runMCPRequests([]map[string]any{
		{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name": "hasp_run",
				"arguments": map[string]any{
					"project_root":  projectB,
					"session_token": sessionReply.SessionToken,
					"env":           map[string]any{"API_TOKEN": "secret_01"},
					"command":       []any{"true"},
				},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "project root mismatch") {
		t.Fatalf("expected project mismatch error, got %v", err)
	}
}

func TestHaspCheckAndUnsupportedToolHelpers(t *testing.T) {
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
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	t.Setenv(mcpEnvSessionToken, "session-token")
	grantMCPProjectSession(t, handle, projectRoot, "session-token")
	if err := os.WriteFile(filepath.Join(projectRoot, "leak.txt"), []byte("abc123"), 0o600); err != nil {
		t.Fatalf("write leak file: %v", err)
	}

	result, err := callCheck(context.Background(), handle, toolCall{
		Name:      "hasp_check",
		Arguments: map[string]any{"project_root": projectRoot},
	})
	if err != nil {
		t.Fatalf("callCheck: %v", err)
	}
	if !strings.Contains(mustJSONMap(t, result), "leak.txt") {
		t.Fatalf("expected leak result, got %v", result)
	}
	if err := approvalRequired("reason"); err == nil || !strings.Contains(err.Error(), "reason") {
		t.Fatalf("expected approvalRequired helper error, got %v", err)
	}
	if err := approvalRequired("secret_session_grant_required"); err == nil || !strings.Contains(err.Error(), "grant_secret") {
		t.Fatalf("expected secret grant recovery hint, got %v", err)
	}
	if err := fmtUnsupportedTool("bogus"); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("expected fmtUnsupportedTool helper error, got %v", err)
	}

	if _, err := callTool(context.Background(), toolCall{Name: "unknown", Arguments: map[string]any{}}); err == nil || !strings.Contains(err.Error(), "unsupported tool") {
		t.Fatalf("expected unsupported tool error, got %v", err)
	}
	if boolArg(map[string]any{"grant_write": "yes"}, "grant_write", false) {
		t.Fatal("expected boolArg to ignore non-bool values")
	}
}

func TestHaspCheckUsesSharedScannerMetadata(t *testing.T) {
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
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123secret"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	t.Setenv(mcpEnvSessionToken, "session-token")
	grantMCPProjectSession(t, handle, projectRoot, "session-token")
	mustGit(t, projectRoot, "init")
	if err := os.WriteFile(filepath.Join(projectRoot, ".gitignore"), []byte("ignored.txt\n"), 0o600); err != nil {
		t.Fatalf("write gitignore: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "raw.txt"), []byte("abc123secret"), 0o600); err != nil {
		t.Fatalf("write raw leak: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "b64.txt"), []byte(base64.StdEncoding.EncodeToString([]byte("abc123secret"))), 0o600); err != nil {
		t.Fatalf("write b64 leak: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "hex.txt"), []byte(hex.EncodeToString([]byte("abc123secret"))), 0o600); err != nil {
		t.Fatalf("write hex leak: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "url.txt"), []byte("token=abc123secret%21"), 0o600); err != nil {
		t.Fatalf("write url leak: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "ignored.txt"), []byte("abc123secret"), 0o600); err != nil {
		t.Fatalf("write ignored leak: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "huge.bin"), bytes.Repeat([]byte("x"), int(reposcan.DefaultMaxFileBytes)+1), 0o600); err != nil {
		t.Fatalf("write huge file: %v", err)
	}

	result, err := callCheck(context.Background(), handle, toolCall{
		Name:      "hasp_check",
		Arguments: map[string]any{"project_root": projectRoot},
	})
	if err != nil {
		t.Fatalf("callCheck: %v", err)
	}

	body := mustJSONMap(t, result)
	for _, name := range []string{"raw.txt", "b64.txt", "hex.txt", "url.txt"} {
		if !strings.Contains(body, name) {
			t.Fatalf("expected %s match in %s", name, body)
		}
	}
	if strings.Contains(body, "ignored.txt") {
		t.Fatalf("expected .gitignore to suppress ignored.txt, got %s", body)
	}
	if !strings.Contains(body, "\"walker\":\"git-ls-files\"") {
		t.Fatalf("expected git-ls-files walker, got %s", body)
	}
	if !strings.Contains(body, "\"path\":\"huge.bin\"") || !strings.Contains(body, "\"reason\":\"over_max_bytes\"") {
		t.Fatalf("expected huge.bin skipped metadata, got %s", body)
	}
}

func TestHaspCheckFallsBackOutsideGit(t *testing.T) {
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
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123secret"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	t.Setenv(mcpEnvSessionToken, "session-token")
	grantMCPProjectSession(t, handle, projectRoot, "session-token")
	if err := os.WriteFile(filepath.Join(projectRoot, "leak.txt"), []byte("abc123secret"), 0o600); err != nil {
		t.Fatalf("write leak: %v", err)
	}

	result, err := callCheck(context.Background(), handle, toolCall{
		Name:      "hasp_check",
		Arguments: map[string]any{"project_root": projectRoot},
	})
	if err != nil {
		t.Fatalf("callCheck: %v", err)
	}
	body := mustJSONMap(t, result)
	if !strings.Contains(body, "\"walker\":\"walkdir\"") {
		t.Fatalf("expected walkdir fallback, got %s", body)
	}
	if !strings.Contains(body, "leak.txt") {
		t.Fatalf("expected leak.txt match, got %s", body)
	}
}

func TestCallExecuteCapsAndRedactsStreamingOutput(t *testing.T) {
	lockMCPSeams(t)
	origEnsureSession := ensureSessionFn
	origResolveBinding := resolveBindingViewMCPFn
	origAuthorizeRef := authorizeReferenceMCPFn
	origRunnerExecute := runnerExecuteMCPFn
	defer func() {
		ensureSessionFn = origEnsureSession
		resolveBindingViewMCPFn = origResolveBinding
		authorizeReferenceMCPFn = origAuthorizeRef
		runnerExecuteMCPFn = origRunnerExecute
	}()

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
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123secret"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "session-token"}, nil
	}
	resolveBindingViewMCPFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{ID: "binding-id"}, nil, nil
	}
	authorizeReferenceMCPFn = func(context.Context, *store.Handle, string, string, string, string, store.Operation, store.GrantScope, store.GrantScope, store.GrantScope, time.Duration, string) (store.Item, error) {
		return store.Item{Name: "api_token", Value: []byte("abc123secret")}, nil
	}
	runnerExecuteMCPFn = func(_ context.Context, input runner.Input) (runner.Result, error) {
		if input.Stdout == nil || input.Stderr == nil {
			t.Fatalf("expected streaming writers to be provided to runner")
		}
		chunk := strings.Repeat("abc123secret\n", mcpToolOutputByteLimit)
		if _, err := io.WriteString(input.Stdout, chunk); err != nil {
			return runner.Result{}, err
		}
		if _, err := io.WriteString(input.Stderr, chunk); err != nil {
			return runner.Result{}, err
		}
		return runner.Result{ExitCode: 0}, nil
	}

	result, err := callExecute(context.Background(), handle, toolCall{
		Name: "hasp_run",
		Arguments: map[string]any{
			"project_root": projectRoot,
			"env":          map[string]any{"API_TOKEN": "secret_01"},
			"command":      []any{"true"},
		},
	})
	if err != nil {
		t.Fatalf("callExecute: %v", err)
	}

	stdout := result["stdout"].(string)
	stderr := result["stderr"].(string)
	if strings.Contains(stdout, "abc123secret") || strings.Contains(stderr, "abc123secret") {
		t.Fatalf("expected redaction, got stdout=%q stderr=%q", stdout, stderr)
	}
	if len(stdout) > mcpToolOutputByteLimit || len(stderr) > mcpToolOutputByteLimit {
		t.Fatalf("expected capped output <= %d bytes, got stdout=%d stderr=%d", mcpToolOutputByteLimit, len(stdout), len(stderr))
	}
	if truncated, ok := result["stdout_truncated"].(bool); !ok || !truncated {
		t.Fatalf("expected stdout_truncated=true, got %v", result["stdout_truncated"])
	}
	if truncated, ok := result["stderr_truncated"].(bool); !ok || !truncated {
		t.Fatalf("expected stderr_truncated=true, got %v", result["stderr_truncated"])
	}
	if omitted, ok := result["stdout_bytes_omitted"].(int64); !ok || omitted <= 0 {
		t.Fatalf("expected stdout_bytes_omitted>0, got %#v", result["stdout_bytes_omitted"])
	}
	if omitted, ok := result["stderr_bytes_omitted"].(int64); !ok || omitted <= 0 {
		t.Fatalf("expected stderr_bytes_omitted>0, got %#v", result["stderr_bytes_omitted"])
	}
	if redacted, ok := result["redacted"].(bool); !ok || !redacted {
		t.Fatalf("expected redacted=true, got %v", result["redacted"])
	}
}

func TestServeRejectsMalformedJSON(t *testing.T) {
	var out bytes.Buffer
	if err := Serve(context.Background(), bytes.NewBufferString("{bad json"), &out); err == nil {
		t.Fatal("expected malformed JSON error")
	}
}

func TestServePropagatesEncodeFailure(t *testing.T) {
	req := bytes.NewBufferString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n")
	if err := Serve(context.Background(), req, failingWriter{err: errors.New("encode fail")}); err == nil {
		t.Fatal("expected encode failure")
	}
}

func TestServeIgnoresNotifications(t *testing.T) {
	var input bytes.Buffer
	var output bytes.Buffer
	enc := json.NewEncoder(&input)
	if err := enc.Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params":  map[string]any{"protocolVersion": currentProtocolVersion},
	}); err != nil {
		t.Fatalf("encode initialize: %v", err)
	}
	if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		t.Fatalf("encode initialized notification: %v", err)
	}
	if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}); err != nil {
		t.Fatalf("encode tools/list: %v", err)
	}

	if err := Serve(context.Background(), &input, &output); err != nil {
		t.Fatalf("serve mcp: %v", err)
	}

	dec := json.NewDecoder(&output)
	var initResp map[string]any
	if err := dec.Decode(&initResp); err != nil {
		t.Fatalf("decode initialize response: %v", err)
	}
	if initResp["id"].(float64) != 1 {
		t.Fatalf("unexpected initialize response id: %+v", initResp)
	}
	if initResp["result"].(map[string]any)["protocolVersion"] != currentProtocolVersion {
		t.Fatalf("unexpected negotiated protocol version: %+v", initResp)
	}

	var listResp map[string]any
	if err := dec.Decode(&listResp); err != nil {
		t.Fatalf("decode tools/list response: %v", err)
	}
	if listResp["id"].(float64) != 2 {
		t.Fatalf("unexpected tools/list response id: %+v", listResp)
	}

	var extra map[string]any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("expected notification to produce no response, got %+v err=%v", extra, err)
	}
}

func TestDispatchCoversInitializeListAndMethodErrors(t *testing.T) {
	initResp := dispatch(context.Background(), request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2026-04-13"}`),
	})
	if initResp.Error != nil {
		t.Fatalf("unexpected initialize error: %+v", initResp.Error)
	}
	initResult := initResp.Result.(map[string]any)
	if initResult["protocolVersion"] != "2026-04-13" {
		t.Fatalf("expected requested supported protocol version, got %+v", initResult)
	}
	serverInfo := initResult["serverInfo"].(map[string]any)
	if serverInfo["name"] != "hasp" {
		t.Fatalf("unexpected server info: %+v", serverInfo)
	}

	fallbackResp := dispatch(context.Background(), request{
		JSONRPC: "2.0",
		ID:      9,
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2099-01-01"}`),
	})
	if fallbackResp.Result.(map[string]any)["protocolVersion"] != currentProtocolVersion {
		t.Fatalf("expected fallback protocol version, got %+v", fallbackResp.Result)
	}

	listResp := dispatch(context.Background(), request{JSONRPC: "2.0", ID: 2, Method: "tools/list"})
	if listResp.Error != nil {
		t.Fatalf("unexpected tools/list error: %+v", listResp.Error)
	}
	if len(listResp.Result.(map[string]any)["tools"].([]tool)) == 0 {
		t.Fatal("expected tools in catalog")
	}

	badParams := dispatch(context.Background(), request{JSONRPC: "2.0", ID: 3, Method: "tools/call", Params: json.RawMessage("{bad json")})
	if badParams.Error == nil || badParams.Error.Code != -32602 {
		t.Fatalf("expected invalid params error, got %+v", badParams.Error)
	}

	missingMethod := dispatch(context.Background(), request{JSONRPC: "2.0", ID: 4, Method: "bogus"})
	if missingMethod.Error == nil || missingMethod.Error.Code != -32601 {
		t.Fatalf("expected method not found error, got %+v", missingMethod.Error)
	}
}

func TestCallToolEdgeCases(t *testing.T) {
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
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	startTestDaemon(t)

	if _, err := callTool(context.Background(), toolCall{Name: "hasp_run", Arguments: map[string]any{}}); err == nil || !strings.Contains(err.Error(), "command is required") {
		t.Fatalf("expected missing command error, got %v", err)
	}
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_inject", Arguments: map[string]any{
		"project_root": projectRoot,
		"command":      []any{"true"},
	}}); err == nil || !strings.Contains(err.Error(), "files are required") {
		t.Fatalf("expected missing files error, got %v", err)
	}
	t.Setenv(mcpEnvUnsafeWriteTools, "1")
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_capture", Arguments: map[string]any{
		"project_root": projectRoot,
	}}); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("expected missing name error, got %v", err)
	}
	result, err := callTool(context.Background(), toolCall{Name: "hasp_redact", Arguments: map[string]any{"text": "token=abc123"}})
	if err != nil {
		t.Fatalf("hasp_redact failed: %v", err)
	}
	if strings.Contains(result["text"].(string), "abc123") {
		t.Fatalf("expected redaction result, got %v", result)
	}
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_check", Arguments: map[string]any{"project_root": filepath.Join(baseDir, "missing")}}); err == nil {
		t.Fatal("expected hasp_check error on missing project")
	}
}

func TestCallListRequiresApprovalWithoutGrantAndOpenHandleConvenience(t *testing.T) {
	lockMCPSeams(t)
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
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	startTestDaemon(t)

	if _, err := callList(context.Background(), handle, toolCall{Name: "hasp_list", Arguments: map[string]any{"project_root": projectRoot}}); err == nil || !strings.Contains(err.Error(), "approval required") {
		t.Fatalf("expected approval required, got %v", err)
	}

	convHome := filepath.Join(baseDir, "conv-home")
	keyring := newMemoryKeyringForMCPTests()
	enableConvenienceUnlockForMCPTests(t, convHome, "secret-password", keyring)
	t.Setenv(paths.EnvHome, convHome)
	t.Setenv("HASP_MASTER_PASSWORD", "")
	origKeyring := defaultKeyringFn
	defer func() { defaultKeyringFn = origKeyring }()
	defaultKeyringFn = func() store.Keyring { return keyring }
	if _, err := openHandle(context.Background()); err != nil {
		t.Fatalf("open handle with convenience unlock: %v", err)
	}
}

func TestOpenHandleAndAppendAuditApprovalSeams(t *testing.T) {
	lockMCPSeams(t)
	origNewStore := newVaultStoreFn
	origNewAudit := newMCPAuditLogFn
	defer func() {
		newVaultStoreFn = origNewStore
		newMCPAuditLogFn = origNewAudit
	}()

	newVaultStoreFn = func(store.Keyring) (*store.Store, error) { return nil, errors.New("store fail") }
	if _, err := openHandle(context.Background()); err == nil || !strings.Contains(err.Error(), "store fail") {
		t.Fatalf("expected store creation failure, got %v", err)
	}

	newMCPAuditLogFn = func() (*audit.Log, error) { return nil, errors.New("audit fail") }
	appendAuditApproval("binding", "item")
}

func TestMCPAuditAppendsUseUnlockedHMACKey(t *testing.T) {
	lockMCPSeams(t)
	origDefaultKeyring := defaultKeyringFn
	defer func() { defaultKeyringFn = origDefaultKeyring }()
	defaultKeyringFn = func() store.Keyring { return nil }

	homeDir := t.TempDir()
	t.Setenv(paths.EnvHome, homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "secret-password")
	vaultStore, err := store.New(nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "secret-password"); err != nil {
		t.Fatalf("init store: %v", err)
	}

	handle, err := openHandle(context.Background())
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	auditKey := handle.AuditHMACKey()
	if len(auditKey) == 0 || len(auditlog.GetHMACKey()) == 0 {
		t.Fatal("expected openHandle to cache the audit HMAC key")
	}

	appendAuditApproval("binding", "item")
	appendSecretAuditMCP(audit.EventCapture, "agent", map[string]any{"action": "secret.test"})

	log, err := audit.New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	events, err := log.Events()
	if err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("expected at least two MCP audit events, got %d", len(events))
	}
	for _, event := range events[len(events)-2:] {
		if event.Scheme != audit.SchemeHMACSHA256V1 {
			t.Fatalf("event %d scheme = %q, want %q", event.Sequence, event.Scheme, audit.SchemeHMACSHA256V1)
		}
	}
	if err := log.WithKey(auditKey).Verify(); err != nil {
		t.Fatalf("verify keyed MCP audit chain: %v", err)
	}
}

func TestCallToolAndSessionBootstrapErrorBranches(t *testing.T) {
	lockMCPSeams(t)
	origNewStore := newVaultStoreFn
	origEnsureSession := ensureSessionFn
	defer func() {
		newVaultStoreFn = origNewStore
		ensureSessionFn = origEnsureSession
	}()

	newVaultStoreFn = func(store.Keyring) (*store.Store, error) { return nil, errors.New("store fail") }
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_list", Arguments: map[string]any{}}); err == nil || !strings.Contains(err.Error(), "store fail") {
		t.Fatalf("expected callTool bootstrap failure, got %v", err)
	}

	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))
	t.Setenv("HASP_MASTER_PASSWORD", "secret-password")
	vaultStore, err := store.New(store.NewDefaultKeyring())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "secret-password"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "secret-password")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	projectRoot := filepath.Join(baseDir, "project")
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{}, errors.New("session fail")
	}
	if _, err := callList(context.Background(), handle, toolCall{Name: "hasp_list", Arguments: map[string]any{"project_root": projectRoot}}); err == nil || !strings.Contains(err.Error(), "session fail") {
		t.Fatalf("expected callList session error, got %v", err)
	}
	if _, err := callCapture(context.Background(), handle, toolCall{Name: "hasp_capture", Arguments: map[string]any{"project_root": projectRoot, "name": "api_token"}}); err == nil || !strings.Contains(err.Error(), "session fail") {
		t.Fatalf("expected callCapture session error, got %v", err)
	}
}

func TestCallCheckAndExecuteResidualErrorBranches(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))
	t.Setenv("HASP_MASTER_PASSWORD", "secret-password")

	vaultStore, err := store.New(store.NewDefaultKeyring())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "secret-password"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "secret-password")
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	projectRoot := filepath.Join(baseDir, "project")
	if err := os.MkdirAll(filepath.Join(projectRoot, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if err := os.Symlink(filepath.Join(projectRoot, "missing-target"), filepath.Join(projectRoot, "broken-link")); err != nil {
		t.Fatalf("create broken symlink: %v", err)
	}
	if _, err := callCheck(context.Background(), handle, toolCall{Name: "hasp_check", Arguments: map[string]any{"project_root": projectRoot}}); err == nil {
		t.Fatal("expected callCheck read error on broken symlink")
	}

	startTestDaemon(t)
	if _, err := callExecute(context.Background(), handle, toolCall{Name: "hasp_run", Arguments: map[string]any{
		"project_root": projectRoot,
		"env":          map[string]any{"API_TOKEN": "missing"},
		"command":      []any{"true"},
	}}); err == nil {
		t.Fatal("expected authorize-reference failure for missing env ref")
	}
	if _, err := callExecute(context.Background(), handle, toolCall{Name: "hasp_run", Arguments: map[string]any{
		"project_root":  projectRoot,
		"grant_project": "window",
		"grant_secret":  "session",
		"env":           map[string]any{"API_TOKEN": "secret_01"},
		"command":       []any{"/definitely-missing-binary"},
	}}); err == nil {
		t.Fatal("expected runner execution failure")
	}
	if _, err := parseScope("bogus", store.GrantOnce); err == nil {
		t.Fatal("expected invalid parseScope to fail closed")
	}
	if _, err := callExecute(context.Background(), handle, toolCall{Name: "hasp_run", Arguments: map[string]any{
		"project_root":  projectRoot,
		"grant_project": "bogus",
		"env":           map[string]any{"API_TOKEN": "secret_01"},
		"command":       []any{"true"},
	}}); err == nil || !strings.Contains(err.Error(), "unsupported grant scope") {
		t.Fatalf("expected invalid grant_project failure, got %v", err)
	}
	if got := stringArg(map[string]any{"project_root": 123}, "project_root", "fallback"); got != "fallback" {
		t.Fatalf("expected stringArg fallback, got %q", got)
	}
}

func TestMCPSeamResidualBranches(t *testing.T) {
	lockMCPSeams(t)
	origEnsureSession := ensureSessionFn
	origResolveBinding := resolveBindingViewMCPFn
	origGrantProject := grantProjectLeaseMCPFn
	origCanonical := canonicalProjectRootMCPFn
	origAuthorizeRef := authorizeReferenceMCPFn
	origRunnerExecute := runnerExecuteMCPFn
	origGetItem := getItemMCPFn
	origCapture := captureMCPFn
	defer func() {
		ensureSessionFn = origEnsureSession
		resolveBindingViewMCPFn = origResolveBinding
		grantProjectLeaseMCPFn = origGrantProject
		canonicalProjectRootMCPFn = origCanonical
		authorizeReferenceMCPFn = origAuthorizeRef
		runnerExecuteMCPFn = origRunnerExecute
		getItemMCPFn = origGetItem
		captureMCPFn = origCapture
	}()

	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))
	t.Setenv("HASP_MASTER_PASSWORD", "secret-password")
	vaultStore, err := store.New(store.NewDefaultKeyring())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "secret-password"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "secret-password")
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	projectRoot := filepath.Join(baseDir, "project")
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	grantMCPProjectSession(t, handle, projectRoot, "token")
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "token"}, nil
	}

	resolveBindingViewMCPFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("binding fail")
	}
	if _, err := callList(context.Background(), handle, toolCall{Name: "hasp_list", Arguments: map[string]any{"project_root": projectRoot}}); err == nil || !strings.Contains(err.Error(), "binding fail") {
		t.Fatalf("expected callList binding failure, got %v", err)
	}
	resolveBindingViewMCPFn = origResolveBinding

	grantProjectLeaseMCPFn = func(*store.Handle, string, string, store.GrantScope, time.Duration) (store.ProjectLease, error) {
		return store.ProjectLease{}, errors.New("grant project fail")
	}
	if _, err := callList(context.Background(), handle, toolCall{Name: "hasp_list", Arguments: map[string]any{"project_root": projectRoot, "grant_project": "window"}}); err == nil || !strings.Contains(err.Error(), "grant project fail") {
		t.Fatalf("expected callList project grant failure, got %v", err)
	}
	grantProjectLeaseMCPFn = origGrantProject

	canonicalProjectRootMCPFn = func(context.Context, string) (string, error) { return "", errors.New("canonical fail") }
	if _, err := callCheck(context.Background(), handle, toolCall{Name: "hasp_check", Arguments: map[string]any{"project_root": projectRoot, "session_token": "token"}}); err == nil || !strings.Contains(err.Error(), "canonical fail") {
		t.Fatalf("expected callCheck canonical failure, got %v", err)
	}
	canonicalProjectRootMCPFn = origCanonical

	resolveBindingViewMCPFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("binding fail")
	}
	if _, err := callExecute(context.Background(), handle, toolCall{Name: "hasp_run", Arguments: map[string]any{"project_root": projectRoot, "command": []any{"true"}}}); err == nil || !strings.Contains(err.Error(), "binding fail") {
		t.Fatalf("expected callExecute binding failure, got %v", err)
	}
	resolveBindingViewMCPFn = origResolveBinding

	authorizeReferenceMCPFn = func(context.Context, *store.Handle, string, string, string, string, store.Operation, store.GrantScope, store.GrantScope, store.GrantScope, time.Duration, string) (store.Item, error) {
		return store.Item{}, errors.New("authorize ref fail")
	}
	if _, err := callExecute(context.Background(), handle, toolCall{Name: "hasp_inject", Arguments: map[string]any{"project_root": projectRoot, "files": map[string]any{"CERT": "secret_01"}, "command": []any{"true"}}}); err == nil || !strings.Contains(err.Error(), "authorize ref fail") {
		t.Fatalf("expected callExecute file authorize failure, got %v", err)
	}
	authorizeReferenceMCPFn = origAuthorizeRef

	getItemMCPFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get item fail") }
	if _, err := callCapture(context.Background(), handle, toolCall{Name: "hasp_capture", Arguments: map[string]any{"project_root": projectRoot, "name": "api_token"}}); err == nil || !strings.Contains(err.Error(), "get item fail") {
		t.Fatalf("expected callCapture get-item failure, got %v", err)
	}
	getItemMCPFn = origGetItem

	resolveBindingViewMCPFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("binding fail")
	}
	if _, err := callCapture(context.Background(), handle, toolCall{Name: "hasp_capture", Arguments: map[string]any{"project_root": projectRoot, "name": "api_token"}}); err == nil || !strings.Contains(err.Error(), "binding fail") {
		t.Fatalf("expected callCapture binding failure, got %v", err)
	}
	resolveBindingViewMCPFn = origResolveBinding

	captureMCPFn = func(*store.Handle, context.Context, string, string, store.ItemKind, []byte, bool) (store.CaptureResult, error) {
		return store.CaptureResult{}, errors.New("capture fail")
	}
	if _, err := callCapture(context.Background(), handle, toolCall{Name: "hasp_capture", Arguments: map[string]any{"project_root": projectRoot, "name": "new_secret", "grant_project": "window", "grant_write": true, "value": "abc"}}); err == nil || !strings.Contains(err.Error(), "capture fail") {
		t.Fatalf("expected callCapture capture failure, got %v", err)
	}

	once, err := parseScope("once", store.GrantWindow)
	if err != nil || once != store.GrantOnce {
		t.Fatalf("expected once scope, got %q err=%v", once, err)
	}
	sessionScope, err := parseScope("session", store.GrantOnce)
	if err != nil || sessionScope != store.GrantSession {
		t.Fatalf("expected session scope, got %q err=%v", sessionScope, err)
	}
	window, err := parseScope("window", store.GrantOnce)
	if err != nil || window != store.GrantWindow {
		t.Fatalf("expected window scope, got %q err=%v", window, err)
	}
	fallback, err := parseScope("", store.GrantSession)
	if err != nil || fallback != store.GrantSession {
		t.Fatalf("expected empty scope fallback, got %q err=%v", fallback, err)
	}
	if _, err := parseScope("later", store.GrantOnce); err == nil {
		t.Fatal("expected parseScope to cover once, session, and window")
	}
}

func enableConvenienceUnlockForMCPTests(t *testing.T, homeDir string, password string, keyring store.Keyring) {
	t.Helper()
	t.Setenv(paths.EnvHome, homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", password)
	vaultStore, err := store.New(keyring)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), password); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), password)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := handle.EnableConvenienceUnlock(context.Background()); err != nil {
		t.Fatalf("enable convenience unlock: %v", err)
	}
}

type mcpMemoryKeyring struct {
	values map[string]string
}

func newMemoryKeyringForMCPTests() *mcpMemoryKeyring {
	return &mcpMemoryKeyring{values: map[string]string{}}
}

func (m *mcpMemoryKeyring) Set(_ context.Context, service string, account string, value string) error {
	m.values[service+"|"+account] = value
	return nil
}

func (m *mcpMemoryKeyring) Get(service string, account string) (string, error) {
	value, ok := m.values[service+"|"+account]
	if !ok {
		return "", store.ErrKeyringUnavailable
	}
	return value, nil
}

func (m *mcpMemoryKeyring) Delete(service string, account string) error {
	delete(m.values, service+"|"+account)
	return nil
}

func mustJSONMap(t *testing.T, value map[string]any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal map: %v", err)
	}
	return string(data)
}

func runMCPRequests(requests []map[string]any) ([]map[string]any, error) {
	var input bytes.Buffer
	var output bytes.Buffer
	enc := json.NewEncoder(&input)
	for _, req := range requests {
		if err := enc.Encode(req); err != nil {
			return nil, err
		}
	}
	if err := Serve(context.Background(), &input, &output); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(&output)
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

func startTestDaemon(t *testing.T) *runtime.Manager {
	t.Helper()

	socketDir, err := os.MkdirTemp("/tmp", "hmcp-")
	if err != nil {
		t.Fatalf("create socket dir: %v", err)
	}
	socketPath := filepath.Join(socketDir, "s.sock")
	t.Setenv(paths.EnvSocket, socketPath)
	t.Cleanup(func() {
		_ = os.Remove(socketPath)
		_ = os.RemoveAll(socketDir)
	})
	manager, err := runtime.NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.RunDaemon(ctx)
	}()
	waitForSocket(t, manager.SocketPath(), errCh)
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("daemon exited: %v", err)
			}
		case <-time.After(10 * time.Second):
			// Tight CI coverage runs (internal/app coverage takes 7+ minutes
			// in the public release lane) leave the runner heavily contended
			// when this cleanup fires. The original 2s cap was just a safety
			// guardrail; widen it to 10s so a slow scheduler tick does not
			// fail an otherwise-clean test, while still bounding any genuine
			// shutdown deadlock.
			t.Fatal("timed out waiting for daemon shutdown")
		}
	})
	return manager
}

func waitForSocket(t *testing.T, socketPath string, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("daemon startup failed: %v", err)
			}
			t.Fatalf("daemon exited before socket became available")
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		client, err := runtime.Dial(ctx, socketPath)
		cancel()
		if err == nil {
			_ = client.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for socket %s", socketPath)
}

func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	if len(args) == 1 && args[0] == "init" {
		if out, err := initTestGitRepo(dir); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return
	}
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}
