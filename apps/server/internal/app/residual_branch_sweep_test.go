package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestResidualBranchSweep(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HOME", homeDir)
	t.Setenv("HASP_HOME", filepath.Join(homeDir, ".hasp"))
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--project-root", projectRoot, "API_TOKEN=abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}

	t.Run("init and audit direct errors", func(t *testing.T) {
		origStore := newVaultStoreFn
		origAudit := newAuditLogFn
		defer func() {
			newVaultStoreFn = origStore
			newAuditLogFn = origAudit
		}()
		newVaultStoreFn = func() (*store.Store, error) { return nil, errors.New("store fail") }
		if err := initCommandWithArgs(context.Background(), nil, io.Discard); err == nil || err.Error() != "store fail" {
			t.Fatalf("expected init store failure, got %v", err)
		}
		newVaultStoreFn = origStore
		newAuditLogFn = func() (*audit.Log, error) { return nil, errors.New("audit fail") }
		if err := auditCommandWithArgs(nil, io.Discard); err == nil || err.Error() != "audit fail" {
			t.Fatalf("expected audit log creation failure, got %v", err)
		}
		if err := initCommandWithArgs(context.Background(), []string{"extra"}, io.Discard); err == nil {
			t.Fatal("expected init usage failure")
		}
		if err := initCommandWithArgs(context.Background(), []string{"--bad"}, io.Discard); err == nil {
			t.Fatal("expected init parse failure")
		}
		if err := auditCommandWithArgs([]string{"extra"}, io.Discard); err == nil {
			t.Fatal("expected audit usage failure")
		}
		if err := auditCommandWithArgs([]string{"--bad"}, io.Discard); err == nil {
			t.Fatal("expected audit parse failure")
		}
		t.Setenv("HASP_MASTER_PASSWORD", "")
		newVaultStoreFn = origStore
		if err := initCommandWithArgs(context.Background(), nil, io.Discard); err == nil {
			t.Fatal("expected init password failure")
		}
		t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	})

	t.Run("project unbind root fallback", func(t *testing.T) {
		origCanonical := projectCanonicalRootFn
		defer func() { projectCanonicalRootFn = origCanonical }()
		projectCanonicalRootFn = func(context.Context, string) (string, error) { return "", errors.New("root fail") }
		var out bytes.Buffer
		if err := projectUnbindCommand(context.Background(), []string{"--project-root", projectRoot}, &out); err != nil {
			t.Fatalf("projectUnbindCommand fallback: %v", err)
		}
		if !bytes.Contains(out.Bytes(), []byte("Project unbound")) {
			t.Fatalf("unexpected project unbind output %q", out.String())
		}
	})

	t.Run("bootstrap profiles branches", func(t *testing.T) {
		var out bytes.Buffer
		if err := bootstrapProfilesCommand(nil, &out); err != nil {
			t.Fatalf("bootstrapProfilesCommand human: %v", err)
		}
		if !bytes.Contains(out.Bytes(), []byte("Bootstrap profiles")) {
			t.Fatalf("unexpected bootstrap profiles output %q", out.String())
		}
	})

	t.Run("runtime command approval failures", func(t *testing.T) {
		starter := newDaemonTestStarter(t)
		origApprove := sessionGrantPlaintextApproveFn
		defer func() { sessionGrantPlaintextApproveFn = origApprove }()
		sessionGrantPlaintextApproveFn = func(runtime.SessionView, string, store.PlaintextAction) error { return errors.New("approval fail") }

		client, err := starter.Connect(context.Background())
		if err != nil {
			t.Fatalf("dial daemon: %v", err)
		}
		defer client.Close()
		reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
			HostLabel:    "agent",
			ProjectRoot:  projectRoot,
			TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
			AgentSafe:    true,
			ConsumerName: "claude-code",
		})
		if err != nil {
			t.Fatalf("open session: %v", err)
		}
		if err := sessionGrantPlaintextCommand(context.Background(), []string{"--token", reply.SessionToken, "--item", "API_TOKEN", "--action", "reveal"}, io.Discard, starter); err == nil || err.Error() != "approval fail" {
			t.Fatalf("expected plaintext approval failure, got %v", err)
		}
	})

	t.Run("secret policy direct branches", func(t *testing.T) {
		handle, err := openVaultHandle(context.Background())
		if err != nil {
			t.Fatalf("open vault: %v", err)
		}
		if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "API_TOKEN"}, store.PolicySession, false); err != nil {
			t.Fatalf("upsert binding: %v", err)
		}
		canonicalRoot, _, err := secretProjectContext(context.Background(), projectRoot)
		if err != nil {
			t.Fatalf("canonical root: %v", err)
		}
		if _, err := handle.UpsertAgentConsumer(store.AgentConsumer{
			Name:        "claude-code",
			AgentID:     "claude-code",
			ProjectRoot: canonicalRoot,
			ConfigPath:  filepath.Join(homeDir, ".claude.json"),
		}); err != nil {
			t.Fatalf("upsert agent consumer: %v", err)
		}

		origGetwd := secretGetwdFn
		defer func() { secretGetwdFn = origGetwd }()
		secretGetwdFn = func() (string, error) { return projectRoot, nil }
		policy, err := secretPlaintextPolicyForContext(context.Background(), handle)
		if err != nil || !policy.Active || policy.Source != "connected_agent_repo" {
			t.Fatalf("expected connected repo policy, got %+v err=%v", policy, err)
		}

		starter := newDaemonTestStarter(t)
		client, err := starter.Connect(context.Background())
		if err != nil {
			t.Fatalf("dial daemon: %v", err)
		}
		defer client.Close()
		reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
			HostLabel:    "agent",
			ProjectRoot:  projectRoot,
			TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
			AgentSafe:    true,
			ConsumerName: "claude-code",
		})
		if err != nil {
			t.Fatalf("open session: %v", err)
		}
		if err := client.RegisterProcess(context.Background(), reply.SessionToken, os.Getpid()); err != nil {
			t.Fatalf("register process: %v", err)
		}
		if _, err := handle.GrantPlaintextUse(reply.SessionToken, "API_TOKEN", store.PlaintextReveal, "user", store.GrantOnce, 0); err != nil {
			t.Fatalf("grant plaintext: %v", err)
		}
		t.Setenv(envSessionToken, reply.SessionToken)
		if err := enforceSecretPlaintextPolicy(context.Background(), handle, "API_TOKEN", store.PlaintextReveal); err != nil {
			t.Fatalf("expected plaintext grant path to allow, got %v", err)
		}

		t.Setenv(envAgentSafeMode, "1")
		t.Setenv(envAgentConsumer, "claude-code")
		t.Setenv(envAgentProjectRoot, canonicalRoot)
		policy, err = secretPlaintextPolicyForContext(context.Background(), handle)
		if err != nil || !policy.Active || policy.Source != "process_tree" && policy.Source != "session" && policy.Source != "env" {
			t.Fatalf("expected active plaintext policy, got %+v err=%v", policy, err)
		}
	})

	t.Run("check repo no-match json", func(t *testing.T) {
		var out bytes.Buffer
		if err := checkRepoCommand(context.Background(), []string{"--project-root", projectRoot, "--json"}, &out); err != nil {
			t.Fatalf("checkRepoCommand json no-match: %v", err)
		}
		if !bytes.Contains(out.Bytes(), []byte(`"matches"`)) {
			t.Fatalf("unexpected checkRepo output %q", out.String())
		}
		out.Reset()
		if err := checkRepoCommand(context.Background(), []string{"--project-root", projectRoot}, &out); err != nil {
			t.Fatalf("checkRepoCommand human no-match: %v", err)
		}
		if !bytes.Contains(out.Bytes(), []byte("Repo check")) {
			t.Fatalf("unexpected checkRepo human output %q", out.String())
		}
	})

	t.Run("secret get branches", func(t *testing.T) {
		var out bytes.Buffer
		if err := secretGetCommand(context.Background(), []string{"--json", "API_TOKEN"}, bytes.NewBuffer(nil), &out, &out); err != nil {
			t.Fatalf("secretGetCommand json metadata: %v", err)
		}
		t.Setenv(envAgentSafeMode, "1")
		if err := secretGetCommand(context.Background(), []string{"--json", "--reveal", "API_TOKEN"}, bytes.NewBuffer(nil), &out, &out); err == nil {
			t.Fatal("expected reveal to remain blocked in agent-safe mode without grant")
		}
		if err := secretGetCommand(context.Background(), []string{"--bad"}, bytes.NewBuffer(nil), &out, &out); err == nil {
			t.Fatal("expected secretGetCommand parse failure")
		}
	})

	t.Run("init and audit json success", func(t *testing.T) {
		freshHome := t.TempDir()
		t.Setenv("HASP_HOME", freshHome)
		t.Setenv("HASP_MASTER_PASSWORD", "fresh-password")
		var out bytes.Buffer
		if err := initCommandWithArgs(context.Background(), []string{"--json"}, &out); err != nil {
			t.Fatalf("initCommandWithArgs json: %v", err)
		}
		if !bytes.Contains(out.Bytes(), []byte(`"status":"initialized"`)) {
			t.Fatalf("unexpected init json %q", out.String())
		}
		out.Reset()
		if err := auditCommandWithArgs([]string{"--json"}, &out); err != nil {
			t.Fatalf("auditCommandWithArgs json: %v", err)
		}
		if !bytes.Contains(out.Bytes(), []byte(`"status":"ok"`)) {
			t.Fatalf("unexpected audit json %q", out.String())
		}
	})

	t.Run("setup write agent configs multi-target success", func(t *testing.T) {
		specs := []setupAgentSpec{
			{ID: "codex-cli", Label: "Codex CLI", Format: "toml", ConfigPath: func(string) string { return filepath.Join(homeDir, ".codex", "config.toml") }},
			{ID: "claude-code", Label: "Claude Code", Format: "json", ConfigPath: func(string) string { return filepath.Join(homeDir, ".claude.json") }},
		}
		outcomes, err := setupWriteAgentConfigs(specs, filepath.Join(homeDir, ".hasp"))
		if err != nil || len(outcomes) != 2 {
			t.Fatalf("setupWriteAgentConfigs multi-target = %+v err=%v", outcomes, err)
		}
	})
}
