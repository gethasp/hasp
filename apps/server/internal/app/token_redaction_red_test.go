package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestSecretRevealBlockedMessageOmitsRawSessionToken(t *testing.T) {
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

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), ioDiscard(), ioDiscard()); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "--expose=always", "API_TOKEN"}, bytes.NewBufferString("abc123\n"), ioDiscard(), ioDiscard()); err != nil {
		t.Fatalf("secret add: %v", err)
	}
	if err := Run(context.Background(), []string{"agent", "connect", "claude-code", "--project-root", projectRoot}, bytes.NewBuffer(nil), ioDiscard(), ioDiscard()); err != nil {
		t.Fatalf("agent connect: %v", err)
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

	var blockedOut bytes.Buffer
	err = Run(context.Background(), []string{"secret", "get", "--reveal", "API_TOKEN"}, bytes.NewBuffer(nil), &blockedOut, &blockedOut)
	if err == nil {
		t.Fatal("expected plaintext reveal to be blocked without an override grant")
	}
	if strings.Contains(err.Error(), reply.SessionToken) || strings.Contains(blockedOut.String(), reply.SessionToken) {
		t.Fatalf("plaintext denial leaked raw session token: err=%q output=%q", err, blockedOut.String())
	}
}

func TestAuditIncidentBundleJSONOmitsRawSessionTokens(t *testing.T) {
	lockAppSeams(t)

	origNewAuditLog := newAuditLogFn
	origAuditEvents := auditEventsFn
	defer func() {
		newAuditLogFn = origNewAuditLog
		auditEventsFn = origAuditEvents
	}()

	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) {
		return []audit.Event{{
			Type:    audit.EventDeny,
			Actor:   "agent",
			Details: map[string]any{"session_token": "session-secret-token", "safe": "kept"},
		}}, nil
	}

	var out bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"--incident-bundle", "--json"}, &out); err != nil {
		t.Fatalf("audit incident bundle json: %v", err)
	}
	if strings.Contains(out.String(), "session-secret-token") {
		t.Fatalf("incident bundle json leaked raw session token: %s", out.String())
	}
}

func TestAuditTimelineOmitsRawSessionTokens(t *testing.T) {
	lockAppSeams(t)

	origNewAuditLog := newAuditLogFn
	origAuditEvents := auditEventsFn
	defer func() {
		newAuditLogFn = origNewAuditLog
		auditEventsFn = origAuditEvents
	}()

	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) {
		return []audit.Event{{
			Type:      audit.EventDeny,
			Actor:     "agent",
			Timestamp: time.Now().UTC(),
			Details:   map[string]any{"session_token": "timeline-secret-token", "reference": "@API_TOKEN"},
		}}, nil
	}

	var out bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"--format=timeline"}, &out); err != nil {
		t.Fatalf("audit timeline: %v", err)
	}
	if strings.Contains(out.String(), "timeline-secret-token") {
		t.Fatalf("timeline output leaked raw session token: %s", out.String())
	}
}
