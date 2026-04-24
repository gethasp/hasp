package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestHumanOutputCommandSurfaces(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	adoptRoot := t.TempDir()
	secondRepo := filepath.Join(adoptRoot, "repo-two")
	if err := os.MkdirAll(secondRepo, 0o700); err != nil {
		t.Fatalf("mkdir second repo: %v", err)
	}
	for _, repo := range []string{projectRoot, secondRepo} {
		if out, err := run("git", "-C", repo, "init"); err != nil {
			t.Fatalf("git init %s: %v: %s", repo, err, out)
		}
	}

	t.Setenv("HOME", homeDir)
	t.Setenv("HASP_HOME", filepath.Join(homeDir, ".hasp"))
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), ioDiscard(), ioDiscard()); err != nil {
		t.Fatalf("run init: %v", err)
	}

	assertOutput := func(args []string, stdin *bytes.Buffer, mustSee string) {
		t.Helper()
		var out bytes.Buffer
		if stdin == nil {
			stdin = bytes.NewBuffer(nil)
		}
		if err := Run(context.Background(), args, stdin, &out, &out); err != nil {
			t.Fatalf("%v: %v output=%q", args, err, out.String())
		}
		if !strings.Contains(out.String(), mustSee) {
			t.Fatalf("%v output missing %q in %q", args, mustSee, out.String())
		}
	}

	assertOutput([]string{"secret", "add", "--project-root", projectRoot, "API_TOKEN=abc123"}, nil, "Secret add")
	assertOutput([]string{"secret", "get", "API_TOKEN"}, nil, "Metadata only")
	assertOutput([]string{"list"}, nil, "Vault secrets")
	assertOutput([]string{"secret", "hide", "--project-root", projectRoot, "API_TOKEN"}, nil, "Secret hide")
	assertOutput([]string{"secret", "expose", "--project-root", projectRoot, "API_TOKEN"}, nil, "Secret expose")

	assertOutput([]string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=API_TOKEN"}, nil, "Project bound")
	assertOutput([]string{"project", "status", "--project-root", projectRoot}, nil, "Visible references")
	assertOutput([]string{"project", "adopt", "--under", adoptRoot, "--preview"}, nil, "Project adoption")

	repoLeak := filepath.Join(projectRoot, ".env")
	if err := os.WriteFile(repoLeak, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write leak file: %v", err)
	}
	assertOutput([]string{"check-repo", "--project-root", projectRoot, "--allow-managed-secrets"}, nil, "Repo check")

	assertOutput([]string{"app", "connect", "myapp", "--cmd", "true", "--project-root", projectRoot, "--env", "OPENAI_API_KEY=API_TOKEN"}, nil, "App connected")
	assertOutput([]string{"app", "list"}, nil, "App consumers")
	assertOutput([]string{"app", "install", "myapp", "--add-to-path=false"}, nil, "App installed")
	assertOutput([]string{"app", "disconnect", "myapp"}, nil, "App disconnected")

	assertOutput([]string{"agent", "connect", "claude-code", "--project-root", projectRoot}, nil, "Agent connected")
	assertOutput([]string{"agent", "list"}, nil, "Agents")
	assertOutput([]string{"agent", "disconnect", "claude-code"}, nil, "Agent disconnected")

	starter := newDaemonTestStarter(t)

	var pingOut bytes.Buffer
	if err := pingCommand(context.Background(), &pingOut, starter); err != nil {
		t.Fatalf("pingCommand: %v", err)
	}
	if !strings.Contains(pingOut.String(), "Daemon reachable") {
		t.Fatalf("unexpected ping output %q", pingOut.String())
	}

	var statusOut bytes.Buffer
	if err := statusCommand(context.Background(), &statusOut, starter); err != nil {
		t.Fatalf("statusCommand: %v", err)
	}
	if !strings.Contains(statusOut.String(), "active_sessions") {
		t.Fatalf("unexpected status output %q", statusOut.String())
	}

	var sessionOpenOut bytes.Buffer
	if err := sessionOpenCommand(context.Background(), []string{"--project-root", projectRoot}, &sessionOpenOut, starter); err != nil {
		t.Fatalf("sessionOpenCommand: %v", err)
	}
	if !strings.Contains(sessionOpenOut.String(), "Session opened") {
		t.Fatalf("unexpected session open output %q", sessionOpenOut.String())
	}

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

	origApprove := sessionGrantPlaintextApproveFn
	defer func() { sessionGrantPlaintextApproveFn = origApprove }()
	sessionGrantPlaintextApproveFn = func(runtime.SessionView, string, store.PlaintextAction) error { return nil }

	var grantOut bytes.Buffer
	if err := sessionGrantPlaintextCommand(context.Background(), []string{"--token", reply.SessionToken, "--item", "API_TOKEN", "--action", "reveal"}, &grantOut, starter); err != nil {
		t.Fatalf("sessionGrantPlaintextCommand: %v", err)
	}
	if !strings.Contains(grantOut.String(), "Plaintext grant") {
		t.Fatalf("unexpected plaintext grant output %q", grantOut.String())
	}

	var resolveOut bytes.Buffer
	if err := sessionResolveCommand(context.Background(), []string{"--token", reply.SessionToken}, &resolveOut, starter); err != nil {
		t.Fatalf("sessionResolveCommand: %v", err)
	}
	if !strings.Contains(resolveOut.String(), "Resolved the requested daemon-backed session") {
		t.Fatalf("unexpected session resolve output %q", resolveOut.String())
	}

	var exportOut bytes.Buffer
	backupPath := filepath.Join(t.TempDir(), "backup.json")
	if err := exportBackupCommand(context.Background(), []string{"--output", backupPath, "--recovery-passphrase", "backup-passphrase"}, &exportOut); err != nil {
		t.Fatalf("exportBackupCommand: %v", err)
	}
	if !strings.Contains(exportOut.String(), "Backup exported") {
		t.Fatalf("unexpected export output %q", exportOut.String())
	}

	restoreHome := t.TempDir()
	t.Setenv("HASP_HOME", restoreHome)
	if err := restoreBackupCommand(context.Background(), []string{"--input", backupPath, "--recovery-passphrase", "backup-passphrase", "--master-password", "restored-password"}, &exportOut); err != nil {
		t.Fatalf("restoreBackupCommand: %v", err)
	}
	if !strings.Contains(exportOut.String(), "Backup restored") {
		t.Fatalf("unexpected restore output %q", exportOut.String())
	}

	t.Setenv("HASP_HOME", filepath.Join(homeDir, ".hasp"))
	assertOutput([]string{"bootstrap", "profiles"}, nil, "Bootstrap profiles")
}

func ioDiscard() *bytes.Buffer {
	return &bytes.Buffer{}
}
