package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestCommandBranchMatrix(t *testing.T) {
	lockAppSeams(t)

	var out bytes.Buffer
	if err := versionCommand([]string{"--json"}, &out); err != nil {
		t.Fatalf("versionCommand json: %v", err)
	}
	var versionPayload map[string]any
	if err := json.Unmarshal(out.Bytes(), &versionPayload); err != nil {
		t.Fatalf("decode version payload: %v", err)
	}
	if versionPayload["version"] == "" {
		t.Fatalf("expected version payload, got %q", out.String())
	}
	if err := versionCommand([]string{"extra"}, &out); err == nil {
		t.Fatal("expected version usage failure")
	}
	if err := versionCommand([]string{"--bad"}, &out); err == nil {
		t.Fatal("expected version parse failure")
	}

	if err := runWithStarter(context.Background(), []string{"list", "--help"}, bytes.NewBuffer(nil), &out, &out, &fakeStarter{}); err != nil {
		t.Fatalf("runWithStarter list help: %v", err)
	}
	if err := runWithStarter(context.Background(), []string{"get", "--help"}, bytes.NewBuffer(nil), &out, &out, &fakeStarter{}); err != nil {
		t.Fatalf("runWithStarter get help: %v", err)
	}
	if err := runWithStarter(context.Background(), []string{"version", "extra"}, bytes.NewBuffer(nil), &out, &out, &fakeStarter{}); err == nil {
		t.Fatal("expected runWithStarter version usage failure")
	}
	if err := agentConsumerCommand(context.Background(), []string{"launch", "--help"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("agent launch help: %v", err)
	}
	if err := agentConsumerCommand(context.Background(), []string{"shell", "--help"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("agent shell help: %v", err)
	}
	if err := agentConsumerCommand(context.Background(), []string{"mcp", "--help"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("agent mcp help: %v", err)
	}
	if err := bootstrapProfilesCommand([]string{"--json"}, &out); err != nil {
		t.Fatalf("bootstrapProfilesCommand json: %v", err)
	}
	if err := bootstrapProfilesCommand([]string{"extra"}, &out); err == nil {
		t.Fatal("expected bootstrap profiles usage failure")
	}
	if err := bootstrapProfilesCommand([]string{"--bad"}, &out); err == nil {
		t.Fatal("expected bootstrap profiles parse failure")
	}

	starter := newDaemonTestStarter(t)
	out.Reset()
	if err := pingCommandWithArgs(context.Background(), []string{"--json"}, &out, starter); err != nil {
		t.Fatalf("pingCommandWithArgs json: %v", err)
	}
	if err := pingCommandWithArgs(context.Background(), []string{"--bad"}, &out, starter); err == nil {
		t.Fatal("expected ping parse failure")
	}
	out.Reset()
	if err := statusCommandWithArgs(context.Background(), []string{"--json"}, &out, starter); err != nil {
		t.Fatalf("statusCommandWithArgs json: %v", err)
	}
	if !json.Valid(out.Bytes()) {
		t.Fatalf("expected json status output, got %q", out.String())
	}
	if err := statusCommandWithArgs(context.Background(), []string{"--bad"}, &out, starter); err == nil {
		t.Fatal("expected status parse failure")
	}
	if err := sessionCommand(context.Background(), []string{"bogus"}, io.Discard, starter); err == nil {
		t.Fatal("expected unknown session subcommand error")
	}
}

func TestSecretPlaintextPolicyHelpers(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, err := handle.UpsertItem("API_TOKEN", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}

	if !envTruthy("missing") == false {
		t.Fatal("expected envTruthy missing false")
	}
	if _, err := parsePlaintextAction("bogus"); err == nil {
		t.Fatal("expected parsePlaintextAction failure")
	}
	if _, _, ok, err := secretSessionFromEnv(context.Background()); err != nil || ok {
		t.Fatalf("expected secretSessionFromEnv empty, got ok=%v err=%v", ok, err)
	}

	if err := enforceSecretPlaintextPolicy(context.Background(), handle, "API_TOKEN", store.PlaintextReveal); err != nil {
		t.Fatalf("expected inactive plaintext policy to allow, got %v", err)
	}
	policy, err := secretPlaintextPolicyForContext(context.Background(), handle)
	if err != nil || policy.Active {
		t.Fatalf("expected inactive plaintext policy, got %+v err=%v", policy, err)
	}

	origNewManager := secretNewManagerFn
	origDial := secretDialRuntimeFn
	defer func() {
		secretNewManagerFn = origNewManager
		secretDialRuntimeFn = origDial
	}()
	secretNewManagerFn = func() (*runtime.Manager, error) { return nil, errors.New("manager fail") }
	t.Setenv(envSessionToken, "session-token")
	if _, _, ok, err := secretSessionFromEnv(context.Background()); err == nil || ok {
		t.Fatalf("expected secretSessionFromEnv manager failure, got ok=%v err=%v", ok, err)
	}
	secretNewManagerFn = origNewManager
	secretDialRuntimeFn = func(context.Context, string) (*runtime.Client, error) { return nil, errors.New("dial fail") }
	if _, _, ok, err := secretSessionFromEnv(context.Background()); err == nil || ok {
		t.Fatalf("expected secretSessionFromEnv dial failure, got ok=%v err=%v", ok, err)
	}
	if _, _, ok, err := secretSessionFromProcessTree(context.Background()); err != nil || ok {
		t.Fatalf("expected secretSessionFromProcessTree dial fallback, got ok=%v err=%v", ok, err)
	}
	secretDialRuntimeFn = origDial
	starter := newDaemonTestStarter(t)
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	t.Setenv(envSessionToken, "missing-token")
	if _, _, ok, err := secretSessionFromEnv(context.Background()); err == nil || ok {
		t.Fatalf("expected secretSessionFromEnv resolve failure, got ok=%v err=%v", ok, err)
	}
	t.Setenv(envAgentSafeMode, "1")
	t.Setenv(envSessionToken, "")
	if err := enforceSecretPlaintextPolicy(context.Background(), handle, "API_TOKEN", store.PlaintextReveal); err == nil || !strings.Contains(err.Error(), "launch the agent through") {
		t.Fatalf("expected env-only plaintext policy to require launch path, got %v", err)
	}
	secondStarter := newDaemonTestStarter(t)
	secondClient, err := secondStarter.Connect(context.Background())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer secondClient.Close()
	reply, err := secondClient.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "agent",
		ProjectRoot:  "/tmp/project",
		TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
		AgentSafe:    true,
		ConsumerName: "cursor",
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	t.Setenv(envSessionToken, reply.SessionToken)
	if err := enforceSecretPlaintextPolicy(context.Background(), handle, "API_TOKEN", store.PlaintextReveal); err == nil || !strings.Contains(err.Error(), "grant-plaintext --token "+reply.SessionToken) {
		t.Fatalf("expected env session-token plaintext policy to require grant path, got %v", err)
	}
	t.Setenv(envSessionToken, "")
	t.Setenv(envAgentConsumer, "cursor")
	t.Setenv(envAgentProjectRoot, "/tmp/project")
	policy, err = secretPlaintextPolicyForContext(context.Background(), handle)
	if err != nil || !policy.Active || policy.Source != "env" {
		t.Fatalf("expected env plaintext policy, got %+v err=%v", policy, err)
	}

	origGetwd := secretGetwdFn
	defer func() { secretGetwdFn = origGetwd }()
	t.Setenv(envAgentSafeMode, "")
	t.Setenv(envSessionToken, "")
	t.Setenv(envAgentConsumer, "")
	t.Setenv(envAgentProjectRoot, "")
	secretGetwdFn = func() (string, error) { return "", errors.New("cwd fail") }
	if _, err := secretPlaintextPolicyForContext(context.Background(), handle); err == nil {
		t.Fatal("expected secretPlaintextPolicyForContext cwd failure")
	}
}
