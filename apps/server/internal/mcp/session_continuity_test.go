package mcp

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/auditlog"
	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestMCPSessionContinuityAcrossToolsAndProjects(t *testing.T) {
	for _, inherited := range []string{"none", "stale", "other-project"} {
		t.Run(inherited, func(t *testing.T) {
			lockMCPSeams(t)
			handle, root := setupMCPTargetFixture(t)
			t.Setenv(mcpEnvSessionToken, "")
			startTestDaemon(t)
			other := filepath.Join(filepath.Dir(root), "other")
			if err := os.MkdirAll(other, 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := handle.UpsertBinding(context.Background(), other, nil, store.PolicySession, false); err != nil {
				t.Fatal(err)
			}
			switch inherited {
			case "stale":
				t.Setenv(mcpEnvSessionToken, "expired-wrapper-token")
			case "other-project":
				session, err := brokerops.EnsureSessionWithManager(context.Background(), other, "", "wrapper")
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv(mcpEnvSessionToken, session.Token)
			}
			client := newMCPProtocolClient(t)
			first := mustMCPToolPayload(t, client.call("hasp_list", map[string]any{"project_root": root, "grant_project": "session"}))
			if first["session_id"] == "" || first["session_id"] == nil {
				t.Fatal("list did not report the daemon session identity")
			}
			expires, _ := first["session_expires_at"].(string)
			if deadline, err := time.Parse(time.RFC3339Nano, expires); err != nil || !deadline.After(time.Now()) {
				t.Fatalf("list did not report a future session deadline: %q", expires)
			}
			mustMCPToolPayload(t, client.call("hasp_targets", map[string]any{"project_root": root}))
			mustMCPToolPayload(t, client.call("hasp_check", map[string]any{"project_root": root}))
			assertMCPSuccessfulRun(t, client.call("hasp_run", map[string]any{
				"project_root": root, "grant_secret": "session", "env": map[string]any{"API_TOKEN": "@api_token"},
				"command": []string{"sh", "-c", "test -n \"$API_TOKEN\""},
			}))
			assertMCPSuccessfulRun(t, client.call("hasp_run", map[string]any{
				"project_root": root, "env": map[string]any{"API_TOKEN": "@api_token"},
				"command": []string{"sh", "-c", "test -n \"$API_TOKEN\""},
			}))
			assertMCPFailure(t, client.call("hasp_list", map[string]any{"project_root": other}), "project_lease_required")
			mustMCPToolPayload(t, client.call("hasp_list", map[string]any{"project_root": other, "grant_project": "session"}))
			mustMCPToolPayload(t, client.call("hasp_targets", map[string]any{"project_root": root}))
			mustMCPToolPayload(t, client.call("hasp_list", map[string]any{"project_root": other}))
			last := mustMCPToolPayload(t, client.call("hasp_list", map[string]any{"project_root": root}))
			if last["session_id"] != first["session_id"] {
				t.Fatal("returning to a project changed its live session identity")
			}
			assertMCPFailure(t, newMCPProtocolClient(t).call("hasp_targets", map[string]any{"project_root": root}), "project_lease_required")
		})
	}
}

func TestMCPSessionExpiryAndRestartRequireFreshConsent(t *testing.T) {
	for _, event := range []string{"expiry", "restart", "revoke"} {
		t.Run(event, func(t *testing.T) {
			lockMCPSeams(t)
			_, root := setupMCPTargetFixture(t)
			manager, restart := startRestartableMCPDaemon(t)
			daemon, err := runtime.Dial(context.Background(), manager.SocketPath())
			if err != nil {
				t.Fatal(err)
			}
			defer daemon.Close()
			ttl := 60000
			if event == "expiry" {
				ttl = 1000
			}
			opened, err := daemon.OpenSession(context.Background(), runtime.OpenSessionRequest{ProjectRoot: root, HostLabel: "wrapper", TTLMillis: ttl})
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv(mcpEnvSessionToken, opened.SessionToken)
			client := newMCPProtocolClient(t)
			mustMCPToolPayload(t, client.call("hasp_list", map[string]any{"project_root": root, "grant_project": "session"}))
			mustMCPToolPayload(t, client.call("hasp_targets", map[string]any{"project_root": root}))
			switch event {
			case "expiry":
				time.Sleep(time.Until(opened.ExpiresAt.Add(10 * time.Millisecond)))
			case "restart":
				_ = daemon.Close()
				restart()
			case "revoke":
				if err := daemon.RevokeSession(context.Background(), opened.SessionToken); err != nil {
					t.Fatal(err)
				}
			}
			assertMCPFailure(t, client.call("hasp_targets", map[string]any{"project_root": root}), "project_lease_required")
			assertMCPFailure(t, client.call("hasp_targets", map[string]any{"project_root": root, "session_token": opened.SessionToken, "grant_project": "session"}), "omit session_token")
			mustMCPToolPayload(t, client.call("hasp_targets", map[string]any{"project_root": root, "grant_project": "session"}))
			mustMCPToolPayload(t, client.call("hasp_check", map[string]any{"project_root": root}))
		})
	}
}

func TestMCPExplicitWrongProjectTokenDoesNotReplaceCachedSession(t *testing.T) {
	lockMCPSeams(t)
	_, root := setupMCPTargetFixture(t)
	t.Setenv(mcpEnvSessionToken, "")
	startTestDaemon(t)
	other := t.TempDir()
	session, err := brokerops.EnsureSessionWithManager(context.Background(), other, "", "other")
	if err != nil {
		t.Fatal(err)
	}
	client := newMCPProtocolClient(t)
	mustMCPToolPayload(t, client.call("hasp_list", map[string]any{"project_root": root, "grant_project": "session"}))
	assertMCPFailure(t, client.call("hasp_targets", map[string]any{"project_root": root, "session_token": session.Token}), "project root mismatch")
	mustMCPToolPayload(t, client.call("hasp_targets", map[string]any{"project_root": root}))
}

func TestMCPCommandWithoutRefsCanGrantForFollowingDiscovery(t *testing.T) {
	lockMCPSeams(t)
	_, root := setupMCPTargetFixture(t)
	t.Setenv(mcpEnvSessionToken, "")
	startTestDaemon(t)
	client := newMCPProtocolClient(t)
	args := map[string]any{"project_root": root, "command": []string{"echo", "lease"}}
	assertMCPFailure(t, client.call("hasp_run", args), "project_lease_required")
	args["grant_project"] = "session"
	assertMCPSuccessfulRun(t, client.call("hasp_run", args))
	mustMCPToolPayload(t, client.call("hasp_targets", map[string]any{"project_root": root}))
	args["env"] = map[string]string{"TOKEN": "@api_token"}
	assertMCPFailure(t, client.call("hasp_run", args), "secret_session_grant_required")
	args["grant_secret"] = "once"
	assertMCPSuccessfulRun(t, client.call("hasp_run", args))
	delete(args, "grant_secret")
	assertMCPFailure(t, client.call("hasp_run", args), "secret_session_grant_required")
}

func assertMCPSuccessfulRun(t *testing.T, response map[string]any) {
	t.Helper()
	result := mustMCPToolPayload(t, response)
	if result["exit_code"] != float64(0) {
		t.Fatalf("brokered command failed: %+v", result)
	}
}

func startGrantedMCPTestSession(t *testing.T, handle *store.Handle, root string) string {
	t.Helper()
	auditlog.SetHMACKey(handle.AuditHMACKey())
	auditlog.EnsureKeyedChainSeed()
	t.Cleanup(auditlog.ClearHMACKey)
	startTestDaemon(t)
	session, err := brokerops.EnsureSessionWithManager(context.Background(), root, "", "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(mcpEnvSessionToken, session.Token)
	grantMCPProjectSession(t, handle, root, session.Token)
	return session.Token
}

func startRestartableMCPDaemon(t *testing.T) (*runtime.Manager, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "hmcp-restart-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv(paths.EnvSocket, filepath.Join(dir, "s.sock"))
	manager, err := runtime.NewManager()
	if err != nil {
		t.Fatal(err)
	}
	var cancel context.CancelFunc
	var done chan error
	stop := func() {
		if cancel == nil {
			return
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("daemon did not stop")
		}
		cancel = nil
	}
	restart := func() {
		stop()
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		done = make(chan error, 1)
		go func() { done <- manager.RunDaemon(ctx) }()
		waitForSocket(t, manager.SocketPath(), done)
	}
	t.Cleanup(stop)
	restart()
	return manager, restart
}

func assertMCPFailure(t *testing.T, response map[string]any, want string) {
	t.Helper()
	failure, _ := response["error"].(map[string]any)
	message, _ := failure["message"].(string)
	if !strings.Contains(message, want) {
		t.Fatalf("want MCP failure %q, got %+v", want, response)
	}
}

type mcpProtocolClient struct {
	t       *testing.T
	conn    net.Conn
	encoder *json.Encoder
	decoder *json.Decoder
	id      int
}

func newMCPProtocolClient(t *testing.T) *mcpProtocolClient {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		done <- Serve(context.Background(), server, server)
	}()
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("MCP connection: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("MCP connection did not close")
		}
	})
	return &mcpProtocolClient{t: t, conn: client, encoder: json.NewEncoder(client), decoder: json.NewDecoder(client)}
}

func (c *mcpProtocolClient) call(name string, arguments map[string]any) map[string]any {
	c.t.Helper()
	c.id++
	if err := c.conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		c.t.Fatal(err)
	}
	if err := c.encoder.Encode(map[string]any{
		"jsonrpc": "2.0", "id": c.id, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": arguments},
	}); err != nil {
		c.t.Fatal(err)
	}
	var response map[string]any
	if err := c.decoder.Decode(&response); err != nil {
		c.t.Fatal(err)
	}
	return response
}
