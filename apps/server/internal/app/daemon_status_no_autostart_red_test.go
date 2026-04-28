package app

// RED tests for hasp-issue: daemon status/ping must not auto-start the daemon.
//
// These tests will FAIL until statusCommandWithArgs and pingCommandWithArgs are
// fixed to bypass EnsureDaemon when no daemon is listening.

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

// noStartStub is a starter that records whether EnsureDaemon was ever called.
// Connect always fails with a connect-refused-style error so the command can't
// reach a real daemon.
type noStartStub struct {
	ensureCalled bool
}

func (n *noStartStub) EnsureDaemon(_ context.Context) error {
	n.ensureCalled = true
	return nil // returns nil so ensureClient proceeds to Connect
}

func (n *noStartStub) Connect(_ context.Context) (*runtime.Client, error) {
	// Simulate no daemon listening — return a dial error.
	return nil, &stubConnectError{"connect: no daemon"}
}

type stubConnectError struct{ msg string }

func (e *stubConnectError) Error() string { return e.msg }

// TestDaemonStatusNoAutostart: `daemon status` with no daemon running must:
//   - print "not running" (human mode) and exit 0
//   - NEVER invoke EnsureDaemon on the starter
func TestDaemonStatusNoAutostart(t *testing.T) {
	stub := &noStartStub{}
	var out bytes.Buffer
	err := statusCommandWithArgs(context.Background(), nil, &out, stub)
	if err != nil {
		t.Fatalf("daemon status: expected nil error when not running, got %v", err)
	}
	if stub.ensureCalled {
		t.Fatal("daemon status: EnsureDaemon was called — daemon was spawned when it should not have been")
	}
	output := out.String()
	if !strings.Contains(strings.ToLower(output), "not running") {
		t.Fatalf("daemon status: expected 'not running' in output, got %q", output)
	}
}

// TestDaemonStatusNoAutostartJSON: `daemon status --json` must return
// {"running":false,...} and NEVER call EnsureDaemon.
func TestDaemonStatusNoAutostartJSON(t *testing.T) {
	stub := &noStartStub{}
	var out bytes.Buffer
	err := statusCommandWithArgs(context.Background(), []string{"--json"}, &out, stub)
	if err != nil {
		t.Fatalf("daemon status --json: expected nil error when not running, got %v", err)
	}
	if stub.ensureCalled {
		t.Fatal("daemon status --json: EnsureDaemon was called — daemon was spawned")
	}
	var payload map[string]any
	if decErr := json.Unmarshal(out.Bytes(), &payload); decErr != nil {
		t.Fatalf("daemon status --json: invalid JSON output %q: %v", out.String(), decErr)
	}
	running, ok := payload["running"]
	if !ok {
		t.Fatalf("daemon status --json: missing 'running' field in %v", payload)
	}
	if running != false {
		t.Fatalf("daemon status --json: expected running=false, got %v", running)
	}
}

// TestDaemonPingNoAutostart: `ping` with no daemon running must:
//   - exit 0
//   - NEVER invoke EnsureDaemon
func TestDaemonPingNoAutostart(t *testing.T) {
	stub := &noStartStub{}
	var out bytes.Buffer
	err := pingCommandWithArgs(context.Background(), nil, &out, stub)
	if err != nil {
		t.Fatalf("ping: expected nil error when not running, got %v", err)
	}
	if stub.ensureCalled {
		t.Fatal("ping: EnsureDaemon was called — daemon was spawned when it should not have been")
	}
	output := out.String()
	if !strings.Contains(strings.ToLower(output), "not running") {
		t.Fatalf("ping: expected 'not running' in output, got %q", output)
	}
}

// TestDaemonPingNoAutostartJSON: `ping --json` must return {"running":false}
// and NEVER call EnsureDaemon.
func TestDaemonPingNoAutostartJSON(t *testing.T) {
	stub := &noStartStub{}
	var out bytes.Buffer
	err := pingCommandWithArgs(context.Background(), []string{"--json"}, &out, stub)
	if err != nil {
		t.Fatalf("ping --json: expected nil error when not running, got %v", err)
	}
	if stub.ensureCalled {
		t.Fatal("ping --json: EnsureDaemon was called — daemon was spawned")
	}
	var payload map[string]any
	if decErr := json.Unmarshal(out.Bytes(), &payload); decErr != nil {
		t.Fatalf("ping --json: invalid JSON output %q: %v", out.String(), decErr)
	}
	running, ok := payload["running"]
	if !ok {
		t.Fatalf("ping --json: missing 'running' field in %v", payload)
	}
	if running != false {
		t.Fatalf("ping --json: expected running=false, got %v", running)
	}
}

// TestDaemonStopThenStatusNoRespawn: simulate stop then status — status must
// not respawn. We use the noStartStub to verify EnsureDaemon is never called
// by statusCommandWithArgs.
func TestDaemonStopThenStatusNoRespawn(t *testing.T) {
	stub := &noStartStub{}
	var out bytes.Buffer
	// After stop, daemon is not running — call status.
	err := statusCommandWithArgs(context.Background(), nil, &out, stub)
	if err != nil {
		t.Fatalf("daemon status after stop: expected nil error, got %v", err)
	}
	if stub.ensureCalled {
		t.Fatal("daemon status after stop: EnsureDaemon was called — daemon respawned")
	}
	output := out.String()
	if !strings.Contains(strings.ToLower(output), "not running") {
		t.Fatalf("daemon status after stop: expected 'not running' in output, got %q", output)
	}
}
