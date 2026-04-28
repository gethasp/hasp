package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/profiles"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestDoctorJSONContainsOnlyAllowlistedKeys(t *testing.T) {
	var out bytes.Buffer
	err := runWithStarter(context.Background(), []string{"doctor", "--json"}, bytes.NewBuffer(nil), &out, io.Discard, &fakeStarter{})
	if err != nil {
		t.Fatalf("doctor --json: %v", err)
	}

	payload := decodeObject(t, out.Bytes())
	allowed := map[string]bool{
		"_schema":             true, // hasp-1dg1: schema-version stamp
		"daemon_running":      true,
		"vault_state":         true,
		"binding_state":       true,
		"hooks_installed":     true,
		"audit_degraded":      true,
		"version_major":       true,
		"version_minor":       true,
		"version_patch":       true,
		"daemon_version":      true, // hasp-8m5h: daemon's reported version (omitempty)
		"version_mismatch":    true, // hasp-8m5h: warn-level mismatch flag
		"redactor_min_length": true,
		"redactor_ansi_aware": true, // hasp-ab5d: ANSI-aware streaming-redaction capability
	}
	for key := range payload {
		if !allowed[key] {
			t.Fatalf("doctor --json exposed non-allowlisted key %q in %+v", key, payload)
		}
	}
	for key := range allowed {
		if _, ok := payload[key]; !ok {
			t.Fatalf("doctor --json missing allowlisted key %q in %+v", key, payload)
		}
	}
}

func TestDoctorHumanReportsDaemonVaultAndBinding(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--hooks=false", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}
	starter := newDaemonTestStarter(t)
	var out bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"doctor", "--project-root", projectRoot}, bytes.NewBuffer(nil), &out, io.Discard, starter); err != nil {
		t.Fatalf("doctor: %v", err)
	}
	text := out.String()
	for _, want := range []string{"daemon", "true", "vault", "unlocked", "binding", "bound", "audit_degraded"} {
		if !strings.Contains(text, want) {
			t.Fatalf("doctor human output missing %q: %s", want, text)
		}
	}
	if err := doctorCommand(context.Background(), []string{"extra"}, io.Discard, starter); err == nil {
		t.Fatal("expected doctor usage error")
	}
	if err := doctorCommand(context.Background(), []string{"--bad"}, io.Discard, starter); err == nil {
		t.Fatal("expected doctor parse error")
	}
}

func TestDoctorReportFallbackBranches(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "")
	originalStatus := doctorRuntimeStatusFn
	t.Cleanup(func() { doctorRuntimeStatusFn = originalStatus })
	degradedAt := time.Date(2026, 4, 23, 8, 0, 0, 0, time.UTC)
	doctorRuntimeStatusFn = func(context.Context, starter) (runtime.StatusResponse, bool) {
		return runtime.StatusResponse{AuditDegraded: true, AuditDegradedAt: &degradedAt}, true
	}
	report := buildDoctorReport(context.Background(), ".", nil)
	if !report.AuditDegraded || report.VaultState != "missing" || !strings.Contains(report.auditDetail, "audit append is degraded") {
		t.Fatalf("expected degraded missing-vault report: %+v", report)
	}

	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	report = buildDoctorReport(context.Background(), t.TempDir(), nil)
	if report.VaultState != "unlocked" || report.BindingState != "unbound" {
		t.Fatalf("expected unlocked/unbound report: %+v", report)
	}
	if _, ok := doctorRuntimeStatus(context.Background(), nil); ok {
		t.Fatal("nil starter should not produce runtime status")
	}
	if _, ok := doctorRuntimeStatus(context.Background(), &fakeStarter{err: io.EOF}); ok {
		t.Fatal("starter ensure failure should not produce runtime status")
	}
}

func TestStatusJSONSurfacesAuditDegradedState(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	starter := newDaemonTestStarter(t)

	var out bytes.Buffer
	err := runWithStarter(context.Background(), []string{"status", "--json"}, bytes.NewBuffer(nil), &out, io.Discard, starter)
	if err != nil {
		t.Fatalf("status --json: %v", err)
	}

	payload := decodeObject(t, out.Bytes())
	if _, ok := payload["audit_degraded"]; !ok {
		t.Fatalf("status --json must surface audit_degraded state, got %+v", payload)
	}
}

func TestSessionRevokeAllRevokesEveryActiveSession(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	starter := newDaemonTestStarter(t)
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect daemon: %v", err)
	}
	defer client.Close()

	for _, host := range []string{"agent-a", "agent-b"} {
		if _, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{HostLabel: host, TTLSeconds: 60}); err != nil {
			t.Fatalf("open session %s: %v", host, err)
		}
	}

	var out bytes.Buffer
	err = runWithStarter(context.Background(), []string{"session", "revoke", "--all", "--json"}, bytes.NewBuffer(nil), &out, io.Discard, starter)
	if err != nil {
		t.Fatalf("session revoke --all: %v", err)
	}
	status, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("status after revoke --all: %v", err)
	}
	if status.ActiveSessions != 0 {
		t.Fatalf("session revoke --all left %d active sessions", status.ActiveSessions)
	}
}

func TestAuditIncidentBundleRedactsSecretValues(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	secretValue := "ber-incident-secret-value"

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--vault-only", "--from-stdin", "API_TOKEN"}, bytes.NewBufferString(secretValue+"\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}

	var out bytes.Buffer
	err := Run(context.Background(), []string{"audit", "--incident-bundle", "--json"}, bytes.NewBuffer(nil), &out, io.Discard)
	if err != nil {
		t.Fatalf("audit --incident-bundle --json: %v", err)
	}
	if strings.Contains(out.String(), secretValue) {
		t.Fatalf("incident bundle leaked secret value: %s", out.String())
	}
	payload := decodeObject(t, out.Bytes())
	if _, ok := payload["events"]; !ok {
		t.Fatalf("incident bundle must include redacted time-ordered events, got %+v", payload)
	}
}

func TestVaultLockCommandReportsLockedState(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	var out bytes.Buffer
	err := Run(context.Background(), []string{"vault", "lock", "--json"}, bytes.NewBuffer(nil), &out, io.Discard)
	if err != nil {
		t.Fatalf("vault lock --json: %v", err)
	}
	payload := decodeObject(t, out.Bytes())
	if payload["vault_state"] != "locked" {
		t.Fatalf("vault lock must report vault_state=locked, got %+v", payload)
	}
}

func TestVaultLockCommandRevokesReachableDaemonAndCoversErrors(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	starter := newDaemonTestStarter(t)
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect daemon: %v", err)
	}
	if _, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{HostLabel: "agent", TTLSeconds: 60}); err != nil {
		t.Fatalf("open session: %v", err)
	}
	_ = client.Close()
	var out bytes.Buffer
	if err := vaultLockCommand(context.Background(), nil, &out, starter); err != nil {
		t.Fatalf("vault lock human: %v", err)
	}
	if !strings.Contains(out.String(), "Revoked sessions") {
		t.Fatalf("unexpected vault lock output: %s", out.String())
	}
	if err := vaultCommand(context.Background(), []string{"bogus"}, io.Discard, starter); err == nil {
		t.Fatal("expected unknown vault subcommand")
	}
	if err := vaultLockCommand(context.Background(), []string{"--bad"}, io.Discard, starter); err == nil {
		t.Fatal("expected vault lock parse error")
	}
	if err := vaultLockCommand(context.Background(), []string{"extra"}, io.Discard, starter); err == nil {
		t.Fatal("expected vault lock usage error")
	}
	errStarter := serveAppRuntimeStarter(t, appRuntimeService{lockErr: errors.New("lock fail")})
	if err := vaultLockCommand(context.Background(), nil, io.Discard, errStarter); err == nil || err.Error() != "lock fail" {
		t.Fatalf("expected lock failure, got %v", err)
	}
	failingDeps := defaultVaultGrantOpsDeps()
	failingDeps.RevokeAllGrants = func(*store.Handle) (int, error) { return 0, errors.New("grant revoke fail") }
	if err := vaultLockCommandWithDeps(context.Background(), []string{"--json"}, io.Discard, starter, failingDeps); err == nil || err.Error() != "grant revoke fail" {
		t.Fatalf("expected grant revoke failure, got %v", err)
	}
	var help bytes.Buffer
	if err := vaultCommand(context.Background(), nil, &help, starter); err != nil || !strings.Contains(help.String(), "hasp vault") {
		t.Fatalf("expected vault help, err=%v out=%s", err, help.String())
	}
}

func TestStatusAuditDegradedTimestampAndSessionRevokeAllBranches(t *testing.T) {
	degradedAt := time.Date(2026, 4, 23, 8, 0, 0, 0, time.UTC)
	starter := serveAppRuntimeStarter(t, appRuntimeService{
		status: runtime.StatusResponse{
			SocketPath:      "/tmp/hasp.sock",
			PID:             123,
			StartedAt:       degradedAt,
			AuditDegraded:   true,
			AuditDegradedAt: &degradedAt,
		},
		revokeAll: runtime.RevokeAllSessionsResponse{RevokedCount: 2},
	})
	var statusOut bytes.Buffer
	if err := statusCommandWithArgs(context.Background(), nil, &statusOut, starter); err != nil {
		t.Fatalf("status human: %v", err)
	}
	if !strings.Contains(statusOut.String(), "audit_degraded_at") {
		t.Fatalf("expected degraded timestamp in status: %s", statusOut.String())
	}

	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	var revokeOut bytes.Buffer
	if err := sessionRevokeCommand(context.Background(), []string{"--all"}, &revokeOut, starter); err != nil {
		t.Fatalf("session revoke all human: %v", err)
	}
	if !strings.Contains(revokeOut.String(), "revoked_all") {
		t.Fatalf("unexpected revoke all output: %s", revokeOut.String())
	}
	if err := sessionRevokeCommand(context.Background(), []string{"--all", "--token", "token"}, io.Discard, starter); err == nil {
		t.Fatal("expected token/all conflict")
	}
	errStarter := serveAppRuntimeStarter(t, appRuntimeService{revokeAllErr: errors.New("revoke all fail")})
	if err := sessionRevokeCommand(context.Background(), []string{"--all"}, io.Discard, errStarter); err == nil || err.Error() != "revoke all fail" {
		t.Fatalf("expected revoke all failure, got %v", err)
	}
	failingDeps := defaultVaultGrantOpsDeps()
	failingDeps.RevokeAllGrants = func(*store.Handle) (int, error) { return 0, errors.New("grant revoke fail") }
	if err := sessionRevokeCommandWithDeps(context.Background(), []string{"--all"}, io.Discard, starter, failingDeps); err == nil || err.Error() != "grant revoke fail" {
		t.Fatalf("expected grant revoke failure, got %v", err)
	}
}

func TestSecretRotateStatesProviderSideCredentialCaveat(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--vault-only", "--from-stdin", "API_TOKEN"}, bytes.NewBufferString("local-only-value\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}

	var out bytes.Buffer
	err := Run(context.Background(), []string{"secret", "rotate", "API_TOKEN"}, bytes.NewBuffer(nil), &out, io.Discard)
	if err != nil {
		t.Fatalf("secret rotate: %v", err)
	}
	if !strings.Contains(strings.ToLower(out.String()), "provider") {
		t.Fatalf("secret rotate output must state provider-side credential rotation remains operator responsibility, got %q", out.String())
	}
}

func TestSecretRotateJSONAndErrorBranches(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--vault-only", "--from-stdin", "API_TOKEN"}, bytes.NewBufferString("local-only-value\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "rotate", "--json", "API_TOKEN"}, bytes.NewBufferString("new-local-value\n"), &out, io.Discard); err != nil {
		t.Fatalf("secret rotate json: %v", err)
	}
	payload := decodeObject(t, out.Bytes())
	if payload["provider_caveat"] == "" {
		t.Fatalf("expected provider caveat: %+v", payload)
	}
	if err := secretRotateCommand(context.Background(), []string{"--bad"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected rotate parse error")
	}
	if err := secretRotateCommand(context.Background(), []string{"MISSING=value"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected missing secret error")
	}
	origOpen := openVaultHandleFn
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault fail") }
	if err := secretRotateCommand(context.Background(), []string{"API_TOKEN=value"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected vault failure, got %v", err)
	}
	openVaultHandleFn = origOpen
	if err := secretRotateCommand(context.Background(), nil, errReader{err: errors.New("input fail")}, io.Discard, io.Discard); err == nil || err.Error() != "input fail" {
		t.Fatalf("expected input failure, got %v", err)
	}
	origUpsert := secretUpsertItemFn
	secretUpsertItemFn = func(*store.Handle, string, store.ItemKind, []byte, store.ItemMetadata) (store.Item, error) {
		return store.Item{}, errors.New("upsert fail")
	}
	if err := secretRotateCommand(context.Background(), []string{"API_TOKEN"}, bytes.NewBufferString("value\n"), io.Discard, io.Discard); err == nil || err.Error() != "upsert fail" {
		t.Fatalf("expected upsert failure, got %v", err)
	}
	secretUpsertItemFn = origUpsert
	origRevoke := secretRevokeGrantsForItemFn
	secretRevokeGrantsForItemFn = func(*store.Handle, string) (int, error) { return 0, errors.New("item revoke fail") }
	if err := secretRotateCommand(context.Background(), []string{"API_TOKEN"}, bytes.NewBufferString("value\n"), io.Discard, io.Discard); err == nil || err.Error() != "item revoke fail" {
		t.Fatalf("expected item revoke failure, got %v", err)
	}
	secretRevokeGrantsForItemFn = origRevoke
}

func TestAgentListSupportedJSONReportsProfileProofFields(t *testing.T) {
	var out bytes.Buffer
	err := runWithStarter(context.Background(), []string{"agent", "list-supported", "--json"}, bytes.NewBuffer(nil), &out, io.Discard, &fakeStarter{})
	if err != nil {
		t.Fatalf("agent list-supported --json: %v", err)
	}
	payload := decodeObject(t, out.Bytes())
	profiles, ok := payload["profiles"].([]any)
	if !ok || len(profiles) == 0 {
		t.Fatalf("agent list-supported must return non-empty profiles array, got %+v", payload)
	}
	first, ok := profiles[0].(map[string]any)
	if !ok {
		t.Fatalf("profile entry must be an object, got %+v", profiles[0])
	}
	for _, key := range []string{"support_tier", "docs_path", "config_path", "release_gate", "evals", "benchmarks", "connect_command", "first_class", "compatibility_label"} {
		if _, ok := first[key]; !ok {
			t.Fatalf("profile entry missing %q: %+v", key, first)
		}
	}
}

func TestAgentListSupportedHumanAndUsage(t *testing.T) {
	var out bytes.Buffer
	if err := agentListSupportedCommand(context.Background(), nil, &out); err != nil {
		t.Fatalf("agent list-supported: %v", err)
	}
	if !strings.Contains(out.String(), "profile") || !strings.Contains(out.String(), "tier") {
		t.Fatalf("unexpected human profile output: %s", out.String())
	}
	if err := agentListSupportedCommand(context.Background(), []string{"extra"}, io.Discard); err == nil {
		t.Fatal("expected list-supported usage error")
	}
	if err := agentListSupportedCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected list-supported parse error")
	}
	origLoad := agentLoadSupportStatusesFn
	agentLoadSupportStatusesFn = func() ([]profiles.SupportStatus, error) { return nil, errors.New("profiles fail") }
	if err := agentListSupportedCommand(context.Background(), nil, io.Discard); err == nil || err.Error() != "profiles fail" {
		t.Fatalf("expected profile load failure, got %v", err)
	}
	agentLoadSupportStatusesFn = origLoad
}

func TestSiblingSubRootBindingsRemainIsolatedInsideOneGitWorktree(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--vault-only", "--from-stdin", "PKG_A_TOKEN"}, bytes.NewBufferString("a-value\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add PKG_A_TOKEN: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--vault-only", "--from-stdin", "PKG_B_TOKEN"}, bytes.NewBufferString("b-value\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add PKG_B_TOKEN: %v", err)
	}

	workspace := t.TempDir()
	if out, err := run("git", "-C", workspace, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	pkgA := filepath.Join(workspace, "packages", "pkg-a")
	pkgB := filepath.Join(workspace, "packages", "pkg-b")
	if err := os.MkdirAll(pkgA, 0o755); err != nil {
		t.Fatalf("mkdir pkg-a: %v", err)
	}
	if err := os.MkdirAll(pkgB, 0o755); err != nil {
		t.Fatalf("mkdir pkg-b: %v", err)
	}

	if err := Run(context.Background(), []string{"project", "bind", "--json", "--hooks=false", "--allow-non-git", "--project-root", pkgA, "--alias", "SERVICE_TOKEN=PKG_A_TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("bind pkg-a sub-root: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--json", "--hooks=false", "--allow-non-git", "--project-root", pkgB, "--alias", "SERVICE_TOKEN=PKG_B_TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("bind pkg-b sub-root: %v", err)
	}

	assertOnlyVisibleItem(t, pkgA, "SERVICE_TOKEN", "PKG_A_TOKEN")
	assertOnlyVisibleItem(t, pkgB, "SERVICE_TOKEN", "PKG_B_TOKEN")
}

func TestSecretAddInteractiveDoesNotEchoPastedSecret(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	secretValue := "ber-pasted-secret-value"
	var out bytes.Buffer
	err := Run(context.Background(), []string{"secret", "add", "--vault-only"}, bytes.NewBufferString("API_TOKEN\n"+secretValue+"\nn\n"), &out, io.Discard)
	if err != nil {
		t.Fatalf("interactive secret add: %v", err)
	}
	if strings.Contains(out.String(), secretValue) {
		t.Fatalf("interactive secret add echoed pasted secret in output: %q", out.String())
	}
}

func TestHaspBerCommandHelpAndAuditRedactionBranches(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	for _, topic := range [][]string{
		{"doctor"},
		{"secret", "rotate"},
		{"agent", "list-supported"},
		{"vault"},
		{"vault", "lock"},
	} {
		var out bytes.Buffer
		if err := printHelpTopic(&out, topic); err != nil {
			t.Fatalf("help %v: %v", topic, err)
		}
		if out.Len() == 0 {
			t.Fatalf("expected help output for %v", topic)
		}
	}
	var doctorHelp bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"doctor", "--help"}, bytes.NewBuffer(nil), &doctorHelp, io.Discard, &fakeStarter{}); err != nil {
		t.Fatalf("doctor help dispatch: %v", err)
	}
	event := redactAuditEvent(auditEventForTest(map[string]any{"value": "secret", "token_value": "token", "safe": "kept"}))
	if event.Details["value"] != "[REDACTED]" || event.Details["token_value"] != "[REDACTED]" || event.Details["safe"] != "kept" {
		t.Fatalf("unexpected redacted event details: %+v", event.Details)
	}
	if redactAuditEvent(auditEventForTest(nil)).Details != nil {
		t.Fatal("expected nil audit details to stay nil")
	}
	var auditOut bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"--incident-bundle"}, &auditOut); err != nil {
		t.Fatalf("audit incident human: %v", err)
	}
	origEvents := auditEventsFn
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return nil, errors.New("events fail") }
	if err := auditCommandWithArgs(context.Background(), []string{"--incident-bundle"}, io.Discard); err == nil || err.Error() != "events fail" {
		t.Fatalf("expected events failure, got %v", err)
	}
	auditEventsFn = origEvents
}

func assertOnlyVisibleItem(t *testing.T, projectRoot string, alias string, itemName string) {
	t.Helper()
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"project", "status", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("project status for %s: %v", projectRoot, err)
	}
	payload := decodeObject(t, out.Bytes())
	visible, ok := payload["visible"].([]any)
	if !ok || len(visible) != 1 {
		t.Fatalf("expected one visible reference for %s, got %+v", projectRoot, payload["visible"])
	}
	ref, ok := visible[0].(map[string]any)
	if !ok {
		t.Fatalf("visible reference must be an object, got %+v", visible[0])
	}
	if ref["alias"] != alias || ref["item_name"] != itemName {
		t.Fatalf("expected %s to expose %s=%s only, got %+v", projectRoot, alias, itemName, ref)
	}
}

func decodeObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode JSON %q: %v", string(data), err)
	}
	return payload
}

func auditEventForTest(details map[string]any) audit.Event {
	return audit.Event{Type: audit.EventCapture, Details: details}
}

type appRuntimeService struct {
	status       runtime.StatusResponse
	revokeAll    runtime.RevokeAllSessionsResponse
	revokeAllErr error
	lock         runtime.LockVaultResponse
	lockErr      error
}

func (s appRuntimeService) Ping(_ runtime.PingRequest, reply *runtime.PingResponse) error {
	*reply = runtime.PingResponse{Name: "hasp", Version: runtime.VersionString(), ServerTime: time.Now().UTC()}
	return nil
}

func (s appRuntimeService) Status(_ runtime.StatusRequest, reply *runtime.StatusResponse) error {
	*reply = s.status
	return nil
}

func (s appRuntimeService) RevokeAllSessions(_ runtime.RevokeAllSessionsRequest, reply *runtime.RevokeAllSessionsResponse) error {
	if s.revokeAllErr != nil {
		return s.revokeAllErr
	}
	*reply = s.revokeAll
	return nil
}

func (s appRuntimeService) LockVault(_ runtime.LockVaultRequest, reply *runtime.LockVaultResponse) error {
	if s.lockErr != nil {
		return s.lockErr
	}
	if s.lock.Locked {
		*reply = s.lock
		return nil
	}
	*reply = runtime.LockVaultResponse{Locked: true}
	return nil
}

type socketStarter struct {
	socketPath string
	ensureErr  error
}

func (s socketStarter) EnsureDaemon(context.Context) error {
	return s.ensureErr
}

func (s socketStarter) Connect(ctx context.Context) (*runtime.Client, error) {
	return runtime.Dial(ctx, s.socketPath)
}

func serveAppRuntimeStarter(t *testing.T, service appRuntimeService) starter {
	t.Helper()
	socketPath := filepath.Join("/tmp", "hasp-app-runtime-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".sock")
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen runtime socket: %v", err)
	}
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", service); err != nil {
		t.Fatalf("register runtime service: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		_ = os.Remove(socketPath)
	})
	return socketStarter{socketPath: socketPath}
}
