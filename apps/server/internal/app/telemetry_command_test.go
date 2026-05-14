package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/telemetry"
)

func withAppTelemetryState(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "telemetry.json")
	origEndpoint := telemetry.Endpoint
	origRandom := telemetry.RandomFn
	t.Cleanup(func() {
		telemetry.Endpoint = origEndpoint
		telemetry.RandomFn = origRandom
	})
	t.Setenv("HASP_TELEMETRY_TEST_STATE", path)
	telemetry.Endpoint = ""
	telemetry.RandomFn = func(p []byte) (int, error) {
		for i := range p {
			p[i] = byte(i + 11)
		}
		return len(p), nil
	}
	return path
}

func TestTelemetryStatusDefaultDisabledNoDaemon(t *testing.T) {
	withAppTelemetryState(t)
	var out bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"telemetry", "status", "--json"}, strings.NewReader(""), &out, &out, &fakeStarter{err: errSentinel}); err != nil {
		t.Fatalf("status: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v out=%s", err, out.String())
	}
	if payload["enabled"] != false {
		t.Fatalf("enabled = %v", payload["enabled"])
	}
	if payload["blocked_by_env"] != false {
		t.Fatalf("blocked_by_env = %v", payload["blocked_by_env"])
	}
}

func TestTelemetryEnableEnvKillSwitchDoesNotPersist(t *testing.T) {
	path := withAppTelemetryState(t)
	t.Setenv(telemetry.EnvDisabled, "1")
	var out bytes.Buffer
	err := runWithStarter(context.Background(), []string{"telemetry", "enable", "--yes"}, strings.NewReader(""), &out, &out, &fakeStarter{})
	if err == nil {
		t.Fatal("expected enable to fail under env kill switch")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("state file exists under kill switch: %v", statErr)
	}
}

func TestTelemetryEnablePreviewAndForget(t *testing.T) {
	path := withAppTelemetryState(t)
	telemetry.Endpoint = telemetry.TrustedEndpoint
	var out bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"telemetry", "enable", "--yes", "--json"}, strings.NewReader(""), &out, &out, &fakeStarter{}); err != nil {
		t.Fatalf("enable: %v", err)
	}
	out.Reset()
	if err := runWithStarter(context.Background(), []string{"telemetry", "preview", "--json"}, strings.NewReader(""), &out, &out, &fakeStarter{}); err != nil {
		t.Fatalf("preview: %v", err)
	}
	var preview map[string]any
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil {
		t.Fatalf("decode preview: %v out=%s", err, out.String())
	}
	if preview["would_send"] != true {
		t.Fatalf("would_send = %v", preview["would_send"])
	}
	if _, ok := preview["payload"].(map[string]any); !ok {
		t.Fatalf("missing preview payload: %v", preview)
	}
	out.Reset()
	if err := runWithStarter(context.Background(), []string{"telemetry", "forget", "--json"}, strings.NewReader(""), &out, &out, &fakeStarter{}); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("forget left state file: %v", err)
	}
}

func TestTelemetryCommandBranchesAndHumanOutput(t *testing.T) {
	withAppTelemetryState(t)
	var out bytes.Buffer
	if err := telemetryCommand(context.Background(), nil, strings.NewReader(""), &out, &out); err != nil {
		t.Fatalf("telemetry help: %v", err)
	}
	if !strings.Contains(out.String(), "telemetry") {
		t.Fatalf("help output = %q", out.String())
	}
	if err := telemetryCommand(context.Background(), []string{"unknown"}, strings.NewReader(""), &out, &out); err == nil {
		t.Fatal("expected unknown subcommand error")
	}
	if err := telemetryCommand(context.Background(), []string{"status", "extra"}, strings.NewReader(""), &out, &out); err == nil {
		t.Fatal("expected status usage error")
	}
	if err := telemetryCommand(context.Background(), []string{"preview", "extra"}, strings.NewReader(""), &out, &out); err == nil {
		t.Fatal("expected preview usage error")
	}
	if err := telemetryCommand(context.Background(), []string{"enable", "extra"}, strings.NewReader(""), &out, &out); err == nil {
		t.Fatal("expected enable usage error")
	}
	if err := telemetryCommand(context.Background(), []string{"disable", "extra"}, strings.NewReader(""), &out, &out); err == nil {
		t.Fatal("expected disable usage error")
	}
	if err := telemetryCommand(context.Background(), []string{"forget", "extra"}, strings.NewReader(""), &out, &out); err == nil {
		t.Fatal("expected forget usage error")
	}

	out.Reset()
	if err := telemetryCommand(context.Background(), []string{"status"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatalf("status human: %v", err)
	}
	if !strings.Contains(out.String(), "telemetry: disabled") {
		t.Fatalf("status output = %q", out.String())
	}
	out.Reset()
	if err := telemetryCommand(context.Background(), []string{"preview"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatalf("preview unavailable: %v", err)
	}
	if !strings.Contains(out.String(), "telemetry preview unavailable") {
		t.Fatalf("preview output = %q", out.String())
	}
}

func TestTelemetryEnablePromptCancelAcceptDisableAndStatusReasons(t *testing.T) {
	withAppTelemetryState(t)
	telemetry.Endpoint = telemetry.TrustedEndpoint
	var out bytes.Buffer
	if err := telemetryCommand(context.Background(), []string{"enable"}, strings.NewReader("n\n"), &out, &out); err == nil {
		t.Fatal("expected telemetry enable cancellation")
	}
	out.Reset()
	if err := telemetryCommand(context.Background(), []string{"enable"}, strings.NewReader("yes\n"), &out, &out); err != nil {
		t.Fatalf("enable with prompt: %v", err)
	}
	if !strings.Contains(out.String(), "telemetry enabled") {
		t.Fatalf("enable output = %q", out.String())
	}
	status, err := telemetryStatus(false)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !status.Enabled || !status.WouldSend || status.Reason != "" {
		t.Fatalf("enabled status = %+v", status)
	}

	state, err := telemetry.DefaultStore().Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	state.LastPingAt = time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	state.Commands24h = 2
	state.CommandsTotal = 4
	if err := telemetry.DefaultStore().Save(state); err != nil {
		t.Fatalf("save state: %v", err)
	}
	out.Reset()
	if err := telemetryCommand(context.Background(), []string{"status"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatalf("status enabled human: %v", err)
	}
	for _, want := range []string{"telemetry: enabled", "endpoint:", "install hash prefix:", "last ping:"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("status output missing %q: %s", want, out.String())
		}
	}

	out.Reset()
	if err := telemetryCommand(context.Background(), []string{"disable"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if !strings.Contains(out.String(), "telemetry disabled") {
		t.Fatalf("disable output = %q", out.String())
	}
	state, err = telemetry.DefaultStore().Load()
	if err != nil {
		t.Fatalf("load disabled state: %v", err)
	}
	state.Enabled = true
	if err := telemetry.DefaultStore().Save(state); err != nil {
		t.Fatalf("save enabled state: %v", err)
	}
	t.Setenv(telemetry.EnvDisabled, "true")
	status, err = telemetryStatus(false)
	if err != nil {
		t.Fatalf("status blocked: %v", err)
	}
	if !status.BlockedByEnv || status.Reason != telemetry.EnvDisabled+" is set" {
		t.Fatalf("blocked status = %+v", status)
	}
	out.Reset()
	if err := telemetryCommand(context.Background(), []string{"status"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatalf("status blocked human: %v", err)
	}
	if !strings.Contains(out.String(), "blocked by "+telemetry.EnvDisabled) {
		t.Fatalf("blocked output = %q", out.String())
	}
}

func TestTelemetryStatusPayloadErrorAndHashPrefixBranches(t *testing.T) {
	withAppTelemetryState(t)
	if _, err := telemetryStatus(true); err != nil {
		t.Fatalf("disabled preview status should not error: %v", err)
	}
	telemetry.Endpoint = telemetry.TrustedEndpoint
	if _, err := telemetry.DefaultStore().Enable(time.Now().UTC()); err != nil {
		t.Fatalf("enable: %v", err)
	}
	origRandom := telemetry.RandomFn
	telemetry.RandomFn = func([]byte) (int, error) { return 0, os.ErrPermission }
	state, err := telemetry.DefaultStore().Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	state.InstallID = ""
	state.InstallYear = 0
	if err := telemetry.DefaultStore().Save(state); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := telemetryStatus(true); err == nil {
		t.Fatal("expected payload build failure")
	}
	telemetry.RandomFn = origRandom

	if got := hashPrefix(" abc "); got != "abc" {
		t.Fatalf("short hash prefix = %q", got)
	}
	if got := hashPrefix("1234567890abcdef"); got != "1234567890ab" {
		t.Fatalf("long hash prefix = %q", got)
	}
}

func TestTelemetryCommandErrorBranches(t *testing.T) {
	withAppTelemetryState(t)
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"status flag", func() error {
			return telemetryStatusCommand(context.Background(), []string{"--bad"}, io.Discard, false)
		}},
		{"preview flag", func() error { return telemetryStatusCommand(context.Background(), []string{"--bad"}, io.Discard, true) }},
		{"enable flag", func() error {
			return telemetryEnableCommand(context.Background(), []string{"--bad"}, strings.NewReader(""), io.Discard)
		}},
		{"disable flag", func() error { return telemetryDisableCommand(context.Background(), []string{"--bad"}, io.Discard) }},
		{"forget flag", func() error {
			return telemetryForgetCommand(context.Background(), []string{"--bad"}, io.Discard, io.Discard)
		}},
	} {
		if err := tc.run(); err == nil {
			t.Fatalf("%s should fail", tc.name)
		}
	}

	writeErr := errWriter{err: os.ErrPermission}
	if err := telemetryStatusCommand(context.Background(), nil, writeErr, false); err == nil {
		t.Fatal("status writer failure should propagate")
	}
	if err := telemetryStatusCommand(context.Background(), nil, writeErr, true); err == nil {
		t.Fatal("preview writer failure should propagate")
	}
	if err := telemetryEnableCommand(context.Background(), nil, strings.NewReader("yes\n"), writeErr); err == nil {
		t.Fatal("enable prompt writer failure should propagate")
	}
	if err := telemetryDisableCommand(context.Background(), nil, writeErr); err == nil {
		t.Fatal("disable writer failure should propagate")
	}
	if err := telemetryForgetCommand(context.Background(), nil, writeErr, io.Discard); err == nil {
		t.Fatal("forget writer failure should propagate")
	}
}

func TestSetupTelemetryOptionDefaultsAndPrompt(t *testing.T) {
	opts := setupOptions{NonInteractive: true}
	if err := setupResolveTelemetryOption(&opts, newSetupPrompter(strings.NewReader(""), &bytes.Buffer{})); err != nil {
		t.Fatalf("noninteractive: %v", err)
	}
	if !opts.Telemetry.set || opts.Telemetry.value {
		t.Fatalf("noninteractive telemetry = %+v, want set false", opts.Telemetry)
	}

	opts = setupOptions{}
	if err := setupResolveTelemetryOption(&opts, newSetupPrompter(strings.NewReader("\n"), &bytes.Buffer{})); err != nil {
		t.Fatalf("interactive default: %v", err)
	}
	if !opts.Telemetry.set || opts.Telemetry.value {
		t.Fatalf("interactive default telemetry = %+v, want false", opts.Telemetry)
	}

	opts = setupOptions{}
	if err := setupResolveTelemetryOption(&opts, newSetupPrompter(strings.NewReader("y\n"), &bytes.Buffer{})); err != nil {
		t.Fatalf("interactive yes: %v", err)
	}
	if !opts.Telemetry.value {
		t.Fatalf("interactive yes telemetry = %+v, want true", opts.Telemetry)
	}

	opts = setupOptions{}
	if err := opts.Telemetry.Set("on"); err != nil {
		t.Fatalf("set on: %v", err)
	}
	if !opts.Telemetry.value {
		t.Fatalf("on telemetry = %+v, want true", opts.Telemetry)
	}
	if err := opts.Telemetry.Set("off"); err != nil {
		t.Fatalf("set off: %v", err)
	}
	if opts.Telemetry.value {
		t.Fatalf("off telemetry = %+v, want false", opts.Telemetry)
	}
}
