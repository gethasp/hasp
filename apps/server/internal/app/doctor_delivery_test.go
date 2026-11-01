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

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestDoctorDeliveryReadinessAndJSONBoundary(t *testing.T) {
	root, starter := setupTargetRuntimeFixture(t)
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range []store.AppConsumer{
		{Name: "missing-command", Command: []string{"hasp-test-command-does-not-exist"}},
		{Name: "missing-ref", Command: []string{"sh"}, Bindings: []store.AppBinding{{SecretName: "absent", Target: "TOKEN", Delivery: store.AppDeliveryEnv}}, LauncherPath: filepath.Join(t.TempDir(), "absent")},
		{Name: "ready-app", Command: []string{"sh"}, Bindings: []store.AppBinding{{SecretName: "OPENAI_API_KEY", Target: "TOKEN", Delivery: store.AppDeliveryEnv}}},
	} {
		if _, err := handle.UpsertAppConsumer(app); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := handle.UpsertAgentConsumer(store.AgentConsumer{Name: "missing-agent", AgentID: "codex-cli", ConfigPath: filepath.Join(t.TempDir(), "absent")}); err != nil {
		t.Fatal(err)
	}
	checks := doctorConsumerChecks(root, handle)
	text := ""
	for _, check := range checks {
		text += check.Name + " " + check.State + " " + check.Detail + "\n"
	}
	for _, want := range []string{"command_missing", "ref_missing", "missing_or_unsafe", "agent_config missing", "review_required", "keychain_convenience not_probed", "ready-app"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in %s", want, text)
		}
	}
	if strings.Contains(text, "sk-web-value") {
		t.Fatal("readiness exposed a value")
	}
	var out bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"doctor", "--json", "--project-root", root}, bytes.NewBuffer(nil), &out, io.Discard, starter); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"missing-command", "ready-app", "sk-web-value", "keychain_convenience", "DeliveryChecks"} {
		if strings.Contains(out.String(), forbidden) {
			t.Fatalf("JSON exposed human diagnostic %s", forbidden)
		}
	}
	out.Reset()
	if err := runWithStarter(context.Background(), []string{"doctor", "--no-color", "--project-root", root}, bytes.NewBuffer(nil), &out, io.Discard, starter); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "command_missing") {
		t.Fatalf("human diagnostics missing: %s", out.String())
	}
}

func TestDoctorDeliveryTempDirectorySafety(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Chmod(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := doctorTempDirectory(outside, root).State; got != "not_created" {
		t.Fatal(got)
	}
	if err := os.Mkdir(filepath.Join(outside, "inject"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := doctorTempDirectory(outside, root).State; got != "ready" {
		t.Fatal(got)
	}
	if err := os.Chmod(filepath.Join(outside, "inject"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := doctorTempDirectory(outside, root).State; got != "unsafe" {
		t.Fatal(got)
	}
	if got := doctorTempDirectory(filepath.Join(root, "runtime"), root).State; got != "inside_project" {
		t.Fatal(got)
	}
	alias := filepath.Join(t.TempDir(), "project")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if got := doctorTempDirectory(filepath.Join(alias, "future", "runtime"), root).State; got != "inside_project" {
		t.Fatalf("missing directory under project alias: %s", got)
	}
	link := filepath.Join(t.TempDir(), "runtime")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if got := doctorTempDirectory(link, root).State; got != "unsafe" {
		t.Fatal(got)
	}
}
