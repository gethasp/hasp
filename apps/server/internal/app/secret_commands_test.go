package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSecretCommandsLifecycleInRepo(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	origGetwd := secretGetwdFn
	defer func() { secretGetwdFn = origGetwd }()
	secretGetwdFn = func() (string, error) { return projectRoot, nil }

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	var addOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "--expose=always", "SAVEDEO_NOTARY_PASSWORD"}, bytes.NewBufferString("abc123\n"), &addOut, &addOut); err != nil {
		t.Fatalf("secret add: %v", err)
	}
	if !strings.Contains(addOut.String(), "secret_01") || !strings.Contains(addOut.String(), "@SAVEDEO_NOTARY_PASSWORD") {
		t.Fatalf("expected repo exposure reference in add output, got %q", addOut.String())
	}

	var getOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "get", "SAVEDEO_NOTARY_PASSWORD"}, bytes.NewBuffer(nil), &getOut, &getOut); err != nil {
		t.Fatalf("secret get: %v", err)
	}
	if strings.Contains(getOut.String(), "abc123") || !strings.Contains(getOut.String(), "@SAVEDEO_NOTARY_PASSWORD") {
		t.Fatalf("expected metadata-only secret get, got %q", getOut.String())
	}

	var listOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "list"}, bytes.NewBuffer(nil), &listOut, &listOut); err != nil {
		t.Fatalf("secret list: %v", err)
	}
	if !strings.Contains(listOut.String(), "@SAVEDEO_NOTARY_PASSWORD") {
		t.Fatalf("expected named reference in secret list output, got %q", listOut.String())
	}

	var revealOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "get", "--reveal", "SAVEDEO_NOTARY_PASSWORD"}, bytes.NewBuffer(nil), &revealOut, &revealOut); err != nil {
		t.Fatalf("secret reveal: %v", err)
	}
	if strings.TrimSpace(revealOut.String()) != "abc123" {
		t.Fatalf("unexpected reveal output %q", revealOut.String())
	}

	if err := Run(context.Background(), []string{"secret", "hide", "SAVEDEO_NOTARY_PASSWORD"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret hide: %v", err)
	}
	var statusOut bytes.Buffer
	if err := Run(context.Background(), []string{"project", "status", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), &statusOut, &statusOut); err != nil {
		t.Fatalf("project status after hide: %v", err)
	}
	var statusPayload map[string]any
	if err := json.Unmarshal(statusOut.Bytes(), &statusPayload); err != nil {
		t.Fatalf("decode status after hide: %v", err)
	}
	if visible, ok := statusPayload["visible"].([]any); !ok || len(visible) != 0 {
		t.Fatalf("expected no visible refs after hide, got %+v", statusPayload["visible"])
	}

	if err := Run(context.Background(), []string{"secret", "expose", "SAVEDEO_NOTARY_PASSWORD"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret expose: %v", err)
	}
	statusOut.Reset()
	if err := Run(context.Background(), []string{"project", "status", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), &statusOut, &statusOut); err != nil {
		t.Fatalf("project status after expose: %v", err)
	}
	statusPayload = map[string]any{}
	if err := json.Unmarshal(statusOut.Bytes(), &statusPayload); err != nil {
		t.Fatalf("decode status after expose: %v", err)
	}
	if visible, ok := statusPayload["visible"].([]any); !ok || len(visible) != 1 {
		t.Fatalf("expected one visible ref after expose, got %+v", statusPayload["visible"])
	}

	if err := Run(context.Background(), []string{"secret", "update", "SAVEDEO_NOTARY_PASSWORD"}, bytes.NewBufferString("rotated\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret update: %v", err)
	}
	revealOut.Reset()
	if err := Run(context.Background(), []string{"secret", "get", "--reveal", "SAVEDEO_NOTARY_PASSWORD"}, bytes.NewBuffer(nil), &revealOut, &revealOut); err != nil {
		t.Fatalf("secret reveal after update: %v", err)
	}
	if strings.TrimSpace(revealOut.String()) != "rotated" {
		t.Fatalf("unexpected revealed value after update %q", revealOut.String())
	}

	if err := Run(context.Background(), []string{"secret", "delete", "--yes", "SAVEDEO_NOTARY_PASSWORD"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret delete: %v", err)
	}
	statusOut.Reset()
	if err := Run(context.Background(), []string{"project", "status", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), &statusOut, &statusOut); err != nil {
		t.Fatalf("project status after delete: %v", err)
	}
	statusPayload = map[string]any{}
	if err := json.Unmarshal(statusOut.Bytes(), &statusPayload); err != nil {
		t.Fatalf("decode status after delete: %v", err)
	}
	if visible, ok := statusPayload["visible"].([]any); !ok || len(visible) != 0 {
		t.Fatalf("expected no visible refs after delete, got %+v", statusPayload["visible"])
	}
	if err := Run(context.Background(), []string{"secret", "get", "SAVEDEO_NOTARY_PASSWORD"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected secret get to fail after delete")
	}

	auditData, err := os.ReadFile(filepath.Join(homeDir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(auditData), "secret.get.reveal") || !strings.Contains(string(auditData), "secret.hide") {
		t.Fatalf("expected reveal and hide actions in audit log, got %q", string(auditData))
	}
}

func TestSecretExposeAcceptsProjectRootAfterName(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "--expose=never", "GEMINI_RAI_KEY"}, bytes.NewBufferString("abc123\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}

	var exposeOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "expose", "GEMINI_RAI_KEY", "--project-root", projectRoot, "--json"}, bytes.NewBuffer(nil), &exposeOut, &exposeOut); err != nil {
		t.Fatalf("secret expose with trailing flags: %v\noutput: %s", err, exposeOut.String())
	}

	var payload struct {
		Exposed []struct {
			Name        string `json:"name"`
			ProjectRoot string `json:"project_root"`
			Reference   string `json:"reference"`
		} `json:"exposed"`
	}
	if err := json.Unmarshal(exposeOut.Bytes(), &payload); err != nil {
		t.Fatalf("decode expose output: %v\n%s", err, exposeOut.String())
	}
	if len(payload.Exposed) != 1 {
		t.Fatalf("expected one exposed secret, got %+v", payload.Exposed)
	}
	expectedRoot, err := filepath.EvalSymlinks(projectRoot)
	if err != nil {
		t.Fatalf("canonical project root: %v", err)
	}
	if payload.Exposed[0].Name != "GEMINI_RAI_KEY" || payload.Exposed[0].ProjectRoot != expectedRoot || payload.Exposed[0].Reference == "" {
		t.Fatalf("unexpected exposure payload: %+v", payload.Exposed[0])
	}
}

func TestSecretAddAcceptsFlagsAfterName(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	nonRepo := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	origGetwd := secretGetwdFn
	defer func() { secretGetwdFn = origGetwd }()
	secretGetwdFn = func() (string, error) { return nonRepo, nil }

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	var addOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "add", "TRAILING_FLAG_KEY", "--from-stdin", "--expose=never", "--json"}, bytes.NewBufferString("abc123\n"), &addOut, &addOut); err != nil {
		t.Fatalf("secret add with trailing flags: %v\noutput: %s", err, addOut.String())
	}

	var payload struct {
		Added []struct {
			Name string `json:"name"`
		} `json:"added"`
	}
	if err := json.Unmarshal(addOut.Bytes(), &payload); err != nil {
		t.Fatalf("decode add output: %v\n%s", err, addOut.String())
	}
	if len(payload.Added) != 1 || payload.Added[0].Name != "TRAILING_FLAG_KEY" {
		t.Fatalf("unexpected add payload: %+v", payload.Added)
	}
}

func TestSecretAddOutsideRepoAndCollisionPolicies(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	nonRepo := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	origGetwd := secretGetwdFn
	defer func() { secretGetwdFn = origGetwd }()
	secretGetwdFn = func() (string, error) { return nonRepo, nil }

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	input := bytes.NewBufferString("OPENAI_API_KEY\nabc123\nn\n")
	if err := Run(context.Background(), []string{"secret", "add"}, input, io.Discard, io.Discard); err != nil {
		t.Fatalf("interactive secret add: %v", err)
	}

	var getOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "get", "OPENAI_API_KEY"}, bytes.NewBuffer(nil), &getOut, &getOut); err != nil {
		t.Fatalf("secret get: %v", err)
	}
	if strings.Contains(getOut.String(), "abc123") || strings.Contains(getOut.String(), "project_root") {
		t.Fatalf("expected vault-only metadata outside repo, got %q", getOut.String())
	}

	var skipOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "add", "--on-conflict", "skip", "--from-stdin", "OPENAI_API_KEY"}, bytes.NewBufferString("rotated\n"), &skipOut, &skipOut); err != nil {
		t.Fatalf("secret add skip collision: %v", err)
	}
	if !strings.Contains(skipOut.String(), "skipped") {
		t.Fatalf("expected skipped collision output, got %q", skipOut.String())
	}

	var revealOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "get", "--reveal", "OPENAI_API_KEY"}, bytes.NewBuffer(nil), &revealOut, &revealOut); err != nil {
		t.Fatalf("secret reveal after skip: %v", err)
	}
	if strings.TrimSpace(revealOut.String()) != "abc123" {
		t.Fatalf("expected original value after skipped collision, got %q", revealOut.String())
	}

	if err := Run(context.Background(), []string{"secret", "update", "MISSING_SECRET=abc"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected missing secret update to fail")
	}
}

func TestSecretRevealBlockedForProtectedAgentRepoAndOverride(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	t.Setenv("HOME", homeDir)
	t.Setenv("HASP_HOME", filepath.Join(homeDir, ".hasp"))
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	origGetwd := secretGetwdFn
	defer func() { secretGetwdFn = origGetwd }()
	secretGetwdFn = func() (string, error) { return projectRoot, nil }

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "--expose=always", "API_TOKEN"}, bytes.NewBufferString("abc123\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}
	if err := Run(context.Background(), []string{"agent", "connect", "claude-code", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("agent connect: %v", err)
	}

	var blockedOut bytes.Buffer
	err := Run(context.Background(), []string{"secret", "get", "--reveal", "API_TOKEN"}, bytes.NewBuffer(nil), &blockedOut, &blockedOut)
	if err == nil || !strings.Contains(err.Error(), "hasp agent launch") {
		t.Fatalf("expected agent-safe plaintext block, got err=%v output=%q", err, blockedOut.String())
	}

	var metadataOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "get", "API_TOKEN"}, bytes.NewBuffer(nil), &metadataOut, &metadataOut); err != nil {
		t.Fatalf("metadata get in protected repo: %v", err)
	}
	if strings.Contains(metadataOut.String(), "abc123") {
		t.Fatalf("expected metadata-only output in protected repo, got %q", metadataOut.String())
	}

	starter := newDaemonTestStarter(t)
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "grant-test",
		ProjectRoot:  projectRoot,
		TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
		AgentSafe:    true,
		ConsumerName: "claude-code",
	})
	if err != nil {
		t.Fatalf("open agent-safe session: %v", err)
	}
	t.Setenv(envSessionToken, reply.SessionToken)
	sessionToken := reply.SessionToken
	if err := Run(context.Background(), []string{"session", "grant-plaintext", "--token", sessionToken, "--item", "API_TOKEN", "--action", "reveal"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("session grant-plaintext: %v", err)
	}

	var revealOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "get", "--reveal", "API_TOKEN"}, bytes.NewBuffer(nil), &revealOut, &revealOut); err != nil {
		t.Fatalf("plaintext reveal after grant: %v", err)
	}
	if !strings.Contains(revealOut.String(), "abc123") {
		t.Fatalf("unexpected reveal output %q", revealOut.String())
	}
	if err := Run(context.Background(), []string{"secret", "get", "--reveal", "API_TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected one-time plaintext grant to be consumed after first reveal")
	}

	auditData, err := os.ReadFile(filepath.Join(homeDir, ".hasp", "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(auditData), "secret.get.plaintext_blocked") || !strings.Contains(string(auditData), "grant.plaintext") || !strings.Contains(string(auditData), "secret.get.plaintext_grant_used") {
		t.Fatalf("expected plaintext deny/grant audit events, got %q", string(auditData))
	}
}

func TestSecretRevealBlockedByExplicitAgentSafeEnv(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	nonRepo := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	t.Setenv(envAgentSafeMode, "1")

	origGetwd := secretGetwdFn
	defer func() { secretGetwdFn = origGetwd }()
	secretGetwdFn = func() (string, error) { return nonRepo, nil }

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "OPENAI_API_KEY"}, bytes.NewBufferString("abc123\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "get", "--copy", "OPENAI_API_KEY"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected explicit agent-safe env to block plaintext copy")
	}

	if err := Run(context.Background(), []string{"session", "grant-plaintext", "--token", "missing", "--item", "OPENAI_API_KEY", "--action", "copy"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected missing session token grant to fail")
	}
}

func TestSecretRevealBlockedByAgentSafeSessionEnvOutsideRepo(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	nonRepo := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	origGetwd := secretGetwdFn
	defer func() { secretGetwdFn = origGetwd }()
	secretGetwdFn = func() (string, error) { return nonRepo, nil }

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--project-root", projectRoot, "--from-stdin", "--expose=always", "API_TOKEN"}, bytes.NewBufferString("abc123\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add in project: %v", err)
	}

	starter := newDaemonTestStarter(t)
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "agent-test",
		ProjectRoot:  projectRoot,
		TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
		AgentSafe:    true,
		ConsumerName: "claude-code",
	})
	if err != nil {
		t.Fatalf("open agent-safe session: %v", err)
	}
	t.Setenv(envSessionToken, reply.SessionToken)

	if err := Run(context.Background(), []string{"secret", "get", "--reveal", "API_TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected agent-safe session env to block plaintext reveal outside repo")
	}

	if err := Run(context.Background(), []string{"session", "grant-plaintext", "--token", reply.SessionToken, "--item", "API_TOKEN", "--action", "reveal"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("grant plaintext for session env: %v", err)
	}

	var revealOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "get", "--reveal", "API_TOKEN"}, bytes.NewBuffer(nil), &revealOut, &revealOut); err != nil {
		t.Fatalf("reveal after session grant: %v", err)
	}
	if !strings.Contains(revealOut.String(), "abc123") {
		t.Fatalf("unexpected reveal after session grant %q", revealOut.String())
	}
}

func TestSecretSessionLookupHelpers(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	starter := newDaemonTestStarter(t)
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "agent-test",
		ProjectRoot:  projectRoot,
		TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
		AgentSafe:    true,
		ConsumerName: "cursor",
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if err := client.RegisterProcess(context.Background(), reply.SessionToken, os.Getpid()); err != nil {
		t.Fatalf("register process: %v", err)
	}

	t.Setenv(envSessionToken, reply.SessionToken)
	session, token, ok, err := secretSessionFromEnv(context.Background())
	if err != nil || !ok || token != reply.SessionToken || !session.AgentSafe {
		t.Fatalf("secretSessionFromEnv = %+v token=%q ok=%v err=%v", session, token, ok, err)
	}
	processSession, processToken, ok, err := secretSessionFromProcessTree(context.Background())
	if err != nil || !ok || processToken != reply.SessionToken || processSession.ConsumerName != "cursor" {
		t.Fatalf("secretSessionFromProcessTree = %+v token=%q ok=%v err=%v", processSession, processToken, ok, err)
	}

	origNewManager := secretNewManagerFn
	defer func() { secretNewManagerFn = origNewManager }()
	secretNewManagerFn = func() (*runtime.Manager, error) { return nil, errors.New("manager fail") }
	if _, _, ok, err := secretSessionFromProcessTree(context.Background()); err == nil || ok {
		t.Fatalf("expected secretSessionFromProcessTree manager failure, got ok=%v err=%v", ok, err)
	}
}

func TestSecretGetAndPolicyAdditionalBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "API_TOKEN"}, bytes.NewBufferString("abc123\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}

	origClipboard := secretClipboardFn
	defer func() { secretClipboardFn = origClipboard }()
	copied := ""
	secretClipboardFn = func(value []byte) error {
		copied = string(value)
		return nil
	}
	var out bytes.Buffer
	if err := secretGetCommand(context.Background(), []string{"--json", "--copy", "API_TOKEN"}, bytes.NewBuffer(nil), &out, &out); err != nil {
		t.Fatalf("secretGetCommand json copy: %v", err)
	}
	if copied != "abc123" {
		t.Fatalf("expected copied value, got %q", copied)
	}
	out.Reset()
	if err := secretGetCommand(context.Background(), []string{"--json", "--reveal", "API_TOKEN"}, bytes.NewBuffer(nil), &out, &out); err != nil {
		t.Fatalf("secretGetCommand json reveal: %v", err)
	}
	// hasp-jx3r: "value" is now nested inside "secret", not at the top level.
	// Check for the nested shape: {"secret":{"value":"abc123",...},...}
	if !strings.Contains(out.String(), "\"value\":\"abc123\"") {
		t.Fatalf("unexpected reveal json (want secret.value=abc123) %q", out.String())
	}
	if err := Run(context.Background(), []string{"set", "--name", "CERT_FILE", "--kind", "file", "--value", "pem"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set file secret: %v", err)
	}
	out.Reset()
	if err := secretGetCommand(context.Background(), []string{"--reveal", "CERT_FILE"}, bytes.NewBuffer(nil), &out, &out); err != nil {
		t.Fatalf("secretGetCommand file reveal: %v", err)
	}
	if !strings.Contains(out.String(), "pem") {
		t.Fatalf("unexpected file reveal output %q", out.String())
	}

	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	t.Setenv(envAgentSafeMode, "1")
	t.Setenv(envAgentConsumer, "claude-code")
	t.Setenv(envAgentProjectRoot, "/tmp/project")
	policy, err := secretPlaintextPolicyForContext(context.Background(), handle)
	if err != nil || !policy.Active || policy.Source != "env" {
		t.Fatalf("expected env plaintext policy, got %+v err=%v", policy, err)
	}
}

func TestSecretPlaintextPolicyErrorBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--project-root", projectRoot, "--from-stdin", "--expose=always", "API_TOKEN"}, bytes.NewBufferString("abc123\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}

	origNewManager := secretNewManagerFn
	defer func() { secretNewManagerFn = origNewManager }()
	secretNewManagerFn = func() (*runtime.Manager, error) { return nil, errors.New("manager fail") }
	if _, err := secretPlaintextPolicyForContext(context.Background(), handle); err == nil || err.Error() != "manager fail" {
		t.Fatalf("expected policy process-tree failure, got %v", err)
	}
	if err := enforceSecretPlaintextPolicy(context.Background(), handle, "API_TOKEN", store.PlaintextReveal); err == nil || err.Error() != "manager fail" {
		t.Fatalf("expected enforce policy lookup failure, got %v", err)
	}
	secretNewManagerFn = origNewManager

	starter := newDaemonTestStarter(t)
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	t.Setenv(envSessionToken, "missing")
	if _, err := secretPlaintextPolicyForContext(context.Background(), handle); err == nil || !strings.Contains(err.Error(), "session not found") {
		t.Fatalf("expected env session resolve failure, got %v", err)
	}
}

func TestEnforceSecretPlaintextPolicyConsumeFailure(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--project-root", projectRoot, "--from-stdin", "--expose=always", "API_TOKEN"}, bytes.NewBufferString("abc123\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
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

	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	// hasp-gvks: a 1-second grant TTL races CI: by the time chmod-readonly
	// and enforceSecretPlaintextPolicy run under heavy load, the grant has
	// already expired, so the policy returns "no grant" instead of the
	// expected vault-write failure.  A generous TTL keeps the assertion
	// focused on the persist-failure path.
	if _, err := handle.GrantPlaintextUse(reply.SessionToken, "API_TOKEN", store.PlaintextReveal, "user", store.GrantOnce, time.Minute); err != nil {
		t.Fatalf("grant plaintext use: %v", err)
	}
	t.Setenv(envSessionToken, reply.SessionToken)
	if err := os.Chmod(homeDir, 0o500); err != nil {
		t.Fatalf("chmod home readonly: %v", err)
	}
	defer func() {
		_ = os.Chmod(homeDir, 0o700)
	}()
	if err := enforceSecretPlaintextPolicy(context.Background(), handle, "API_TOKEN", store.PlaintextReveal); err == nil || !strings.Contains(err.Error(), "write temp vault") {
		t.Fatalf("expected consume plaintext persist failure, got %v", err)
	}
}

func TestSecretRevealBlockedByRegisteredProcessTreeOutsideRepo(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	nonRepo := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	origGetwd := secretGetwdFn
	defer func() { secretGetwdFn = origGetwd }()
	secretGetwdFn = func() (string, error) { return nonRepo, nil }

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--project-root", projectRoot, "--from-stdin", "--expose=always", "API_TOKEN"}, bytes.NewBufferString("abc123\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add in project: %v", err)
	}

	starter := newDaemonTestStarter(t)
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "agent-process-tree",
		ProjectRoot:  projectRoot,
		TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
		AgentSafe:    true,
		ConsumerName: "claude-code",
	})
	if err != nil {
		t.Fatalf("open agent-safe session: %v", err)
	}
	if err := client.RegisterProcess(context.Background(), reply.SessionToken, os.Getpid()); err != nil {
		t.Fatalf("register protected process: %v", err)
	}

	err = Run(context.Background(), []string{"secret", "get", "--reveal", "API_TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "grant-plaintext --item API_TOKEN --action reveal") || strings.Contains(err.Error(), reply.SessionToken) {
		t.Fatalf("expected process-tree plaintext block with token-safe grant guidance, got %v", err)
	}
}

func TestSessionGrantPlaintextRejectsSessionScope(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--project-root", projectRoot, "--from-stdin", "--expose=always", "API_TOKEN"}, bytes.NewBufferString("abc123\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add in project: %v", err)
	}

	starter := newDaemonTestStarter(t)
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "agent-scope-test",
		ProjectRoot:  projectRoot,
		TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
		AgentSafe:    true,
		ConsumerName: "claude-code",
	})
	if err != nil {
		t.Fatalf("open agent-safe session: %v", err)
	}

	err = Run(context.Background(), []string{
		"session", "grant-plaintext",
		"--token", reply.SessionToken,
		"--item", "API_TOKEN",
		"--action", "reveal",
		"--scope", "session",
	}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--scope \"once\"") {
		t.Fatalf("expected session-scope rejection, got %v", err)
	}
}
