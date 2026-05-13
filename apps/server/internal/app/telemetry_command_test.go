package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
