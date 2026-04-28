package app

// hasp-zm35: --json must reach every renderer, including the
// "daemon not running" path used by `hasp ping` / `hasp status` and the
// `hasp tui` JSON branch. Pre-fix these checked only their local flag and
// silently dropped ambient `--json`.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

// notRunningStarter implements starter so .Connect always errors, which causes
// connectIfRunning() to return nil and trip the renderNotRunning branch.
type notRunningStarter struct{}

func (notRunningStarter) EnsureDaemon(context.Context) error      { return nil }
func (notRunningStarter) Connect(context.Context) (*runtime.Client, error) {
	return nil, errors.New("not running")
}

func ctxWithGlobalJSON() context.Context {
	gf := globalFlagsFromContext(context.Background())
	gf.json = true
	return contextWithGlobalFlags(context.Background(), gf)
}

func TestPingHonorsAmbientJSONWhenDaemonNotRunning(t *testing.T) {
	var stdout bytes.Buffer
	if err := pingCommandWithArgs(ctxWithGlobalJSON(), nil, &stdout, notRunningStarter{}); err != nil {
		t.Fatalf("pingCommandWithArgs: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("ambient --json should produce JSON output, got %q (err=%v)", stdout.String(), err)
	}
	if payload["running"] != false {
		t.Fatalf("expected running=false in JSON; got %v", payload)
	}
}

func TestStatusHonorsAmbientJSONWhenDaemonNotRunning(t *testing.T) {
	var stdout bytes.Buffer
	if err := statusCommandWithArgs(ctxWithGlobalJSON(), nil, &stdout, notRunningStarter{}); err != nil {
		t.Fatalf("statusCommandWithArgs: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("ambient --json should produce JSON output, got %q (err=%v)", stdout.String(), err)
	}
	if payload["running"] != false {
		t.Fatalf("expected running=false in JSON; got %v", payload)
	}
}

func TestRenderSimpleActionHonorsAmbientQuiet(t *testing.T) {
	gf := globalFlagsFromContext(context.Background())
	gf.quiet = true
	ctx := contextWithGlobalFlags(context.Background(), gf)

	var stdout bytes.Buffer
	if err := renderSimpleAction(ctx, &stdout, "My title", "My lead", cliPair("Key", "value")); err != nil {
		t.Fatalf("renderSimpleAction: %v", err)
	}
	body := stdout.String()
	if bytes.Contains([]byte(body), []byte("My title")) {
		t.Fatalf("--quiet should suppress stage title, got %q", body)
	}
	if bytes.Contains([]byte(body), []byte("My lead")) {
		t.Fatalf("--quiet should suppress success-lead, got %q", body)
	}
	if !bytes.Contains([]byte(body), []byte("value")) {
		t.Fatalf("--quiet must keep the actionable details, got %q", body)
	}
}

func TestTUIHonorsAmbientJSON(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "test-password-123")
	tempDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tempDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	// Initialise the vault so tuiCommand can open it.
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	var stdout bytes.Buffer
	// Note: NO local --json flag. We rely on ambient --json from ctx.
	err := tuiCommand(ctxWithGlobalJSON(), []string{"--project-root", tempDir}, &stdout, io.Discard)
	if err != nil {
		t.Fatalf("tuiCommand: %v", err)
	}
	if len(stdout.Bytes()) == 0 {
		t.Fatal("tuiCommand produced no output")
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("ambient --json must produce JSON; got %q (err=%v)", stdout.String(), err)
	}
}
