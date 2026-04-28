package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

// hasp-w37v: Operators today have no listing command — daemon Status RPC
// already returns SessionView snapshots, but no CLI surface exposes them
// in a human-readable form. These tests pin the behavior of
// `hasp session list`: it must roll up every active session, render the
// columns the operator needs (id, host_label, project_root, last_seen),
// and the --mine variant must filter to the calling user's own sessions.

func TestSessionListCommandRendersActiveSessions(t *testing.T) {
	lockAppSeams(t)
	starter := newDaemonTestStarter(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	connectClient := func() *runtime.Client {
		c, err := starter.Connect(context.Background())
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		return c
	}
	client := connectClient()
	defer client.Close()

	reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:   "session-list-test",
		ProjectRoot: t.TempDir(),
		TTLSeconds:  int(runtime.DefaultSessionTTL.Seconds()),
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	var listOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"session", "list"}, bytes.NewBuffer(nil), &listOut, &listOut, starter); err != nil {
		t.Fatalf("session list: %v", err)
	}
	out := listOut.String()
	if !strings.Contains(out, reply.SessionID) {
		t.Fatalf("expected session id in human output, got %q", out)
	}
	if !strings.Contains(out, "session-list-test") {
		t.Fatalf("expected host label in human output, got %q", out)
	}
}

func TestSessionListCommandJSONReturnsSessionsArray(t *testing.T) {
	lockAppSeams(t)
	starter := newDaemonTestStarter(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	if _, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:   "json-list-test",
		ProjectRoot: t.TempDir(),
		TTLSeconds:  int(runtime.DefaultSessionTTL.Seconds()),
	}); err != nil {
		t.Fatalf("open session: %v", err)
	}

	var listOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"session", "list", "--json"}, bytes.NewBuffer(nil), &listOut, &listOut, starter); err != nil {
		t.Fatalf("session list --json: %v", err)
	}
	var payload struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(listOut.Bytes(), &payload); err != nil {
		t.Fatalf("decode session list json: %v", err)
	}
	if len(payload.Sessions) == 0 {
		t.Fatalf("expected at least one session in JSON output, got %s", listOut.String())
	}
	first := payload.Sessions[0]
	for _, key := range []string{"id", "host_label", "project_root", "expires_at", "last_seen_at"} {
		if _, ok := first[key]; !ok {
			t.Fatalf("expected session JSON to contain %q, got keys %v", key, first)
		}
	}
}

func TestSessionListCommandMineFiltersByLocalUser(t *testing.T) {
	lockAppSeams(t)
	starter := newDaemonTestStarter(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	if _, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:   "mine-test",
		ProjectRoot: t.TempDir(),
		TTLSeconds:  int(runtime.DefaultSessionTTL.Seconds()),
	}); err != nil {
		t.Fatalf("open session: %v", err)
	}

	var listOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"session", "list", "--mine", "--json"}, bytes.NewBuffer(nil), &listOut, &listOut, starter); err != nil {
		t.Fatalf("session list --mine: %v", err)
	}
	var payload struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(listOut.Bytes(), &payload); err != nil {
		t.Fatalf("decode --mine output: %v", err)
	}
	if len(payload.Sessions) == 0 {
		t.Fatalf("--mine should still surface sessions opened by the current user, got %s", listOut.String())
	}
}
