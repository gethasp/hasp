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

	"github.com/gethasp/hasp/apps/server/internal/profiles"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type failingBootstrapWriter struct {
	err error
}

func (w failingBootstrapWriter) Write(p []byte) (int, error) {
	return 0, w.err
}

func TestStringListFlagsHelpers(t *testing.T) {
	var list stringListFlags
	if list.String() != "" {
		t.Fatalf("expected empty string, got %q", list.String())
	}
	var nilList *stringListFlags
	if nilList.String() != "" {
		t.Fatalf("expected nil list string to be empty, got %q", nilList.String())
	}
	if err := list.Set(""); err == nil {
		t.Fatal("expected empty item error")
	}
	if err := list.Set(" api_token "); err != nil {
		t.Fatalf("set item: %v", err)
	}
	if got := list.String(); got != "api_token" {
		t.Fatalf("unexpected list string %q", got)
	}
}

func TestBootstrapProfilesCommandListsReleaseGates(t *testing.T) {
	var out bytes.Buffer
	if err := bootstrapCommand(context.Background(), []string{"profiles", "--json"}, &out); err != nil {
		t.Fatalf("bootstrap profiles: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("decode profiles output: %v", err)
	}
	profilesValue, ok := result["profiles"].([]any)
	if !ok || len(profilesValue) == 0 {
		t.Fatalf("expected profile listing, got %v", result["profiles"])
	}
	first := profilesValue[0].(map[string]any)
	if _, ok := first["release_gate"]; !ok {
		t.Fatalf("expected release gate data in %v", first)
	}
	if first["support_tier"] != profiles.SupportTierFirstClassShipped {
		t.Fatalf("expected first-class support tier, got %v", first["support_tier"])
	}
	if _, ok := first["proof"]; !ok {
		t.Fatalf("expected proof status in %v", first)
	}
	if _, ok := result["generic_path"].(map[string]any); !ok {
		t.Fatalf("expected generic path in %v", result)
	}

	out.Reset()
	if err := Run(context.Background(), []string{"bootstrap", "profiles", "--json"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("run bootstrap profiles: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("expected bootstrap profiles output through Run")
	}
}

func TestBootstrapCommandInitializesBindsAndVerifies(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	var out bytes.Buffer
	if err := bootstrapCommand(context.Background(), []string{"--json", "--profile", "claude-code", "--project-root", projectRoot, "--hooks=false"}, &out); err != nil {
		t.Fatalf("bootstrap command: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("decode bootstrap output: %v", err)
	}
	if result["init_state"] != "created" {
		t.Fatalf("unexpected bootstrap result: %+v", result)
	}
	profile := result["profile"].(map[string]any)
	if profile["id"] != "claude-code" {
		t.Fatalf("unexpected profile: %+v", profile)
	}
	verification := result["verification"].(map[string]any)
	if verification["ready"] != true {
		t.Fatalf("expected ready verification, got %+v", verification)
	}
	if result["release_gate"] == nil {
		t.Fatalf("expected release gate in bootstrap output")
	}

	if err := setCommand(context.Background(), []string{"--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set item for alias binding: %v", err)
	}
	if err := bootstrapCommand(context.Background(), []string{"--profile", "claude-code", "--project-root", projectRoot, "--hooks=false", "--bind-item", "api_token", "--verify=false"}, io.Discard); err != nil {
		t.Fatalf("bootstrap alias update: %v", err)
	}

	var status bytes.Buffer
	if err := projectStatusCommand(context.Background(), []string{"--project-root", projectRoot}, &status); err != nil {
		t.Fatalf("project status: %v", err)
	}
	if !strings.Contains(status.String(), "secret_01") {
		t.Fatalf("expected alias after bootstrap, got %q", status.String())
	}
}

func TestBootstrapCommandImportsAndGenericPath(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	stdinImport := bytes.NewBufferString("export API_TOKEN='abc123'\n")
	var out bytes.Buffer
	if err := bootstrapCommandWithInput(context.Background(), []string{"--json", "--profile", "claude-code", "--project-root", projectRoot, "--hooks=false", "--import", "-", "--bind-imports"}, stdinImport, &out, bootstrapVerification); err != nil {
		t.Fatalf("bootstrap import stdin: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode bootstrap import output: %v", err)
	}
	imported, ok := payload["imported"].([]any)
	if !ok || len(imported) != 1 {
		t.Fatalf("expected imported item payload, got %v", payload["imported"])
	}
	if imported[0].(map[string]any)["alias"] != "secret_01" {
		t.Fatalf("expected imported alias secret_01, got %v", imported[0])
	}
	previews, ok := payload["import_previews"].([]any)
	if !ok || len(previews) != 1 {
		t.Fatalf("expected import preview payload, got %v", payload["import_previews"])
	}
	preview := previews[0].(map[string]any)
	if preview["source"] != "stdin" || preview["local_hygiene_path"] != true {
		t.Fatalf("expected stdin hygiene preview, got %v", preview)
	}

	out.Reset()
	if err := bootstrapCommand(context.Background(), []string{"generic", "--json", "--project-root", projectRoot, "--hooks=false"}, &out); err != nil {
		t.Fatalf("generic bootstrap: %v", err)
	}
	payload = map[string]any{}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode generic bootstrap output: %v", err)
	}
	if payload["support_tier"] != profiles.SupportTierGenericCompatible || payload["first_class"] != false {
		t.Fatalf("unexpected generic support payload: %v", payload)
	}
	profile := payload["profile"].(map[string]any)
	if profile["id"] != "generic" {
		t.Fatalf("expected generic profile id, got %v", profile)
	}
}

func TestBootstrapDoctorReportsPreviewWithoutOverclaiming(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	var out bytes.Buffer
	if err := bootstrapCommandWithInput(context.Background(), []string{"doctor", "--json", "--profile", "claude-code", "--project-root", projectRoot, "--hooks=false", "--import", "-", "--bind-imports"}, bytes.NewBufferString("API_TOKEN=abc123\n"), &out, bootstrapVerification); err != nil {
		t.Fatalf("bootstrap doctor: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode bootstrap doctor output: %v", err)
	}
	if payload["vault_status"] != "would_create" {
		t.Fatalf("expected would_create vault status, got %v", payload["vault_status"])
	}
	transport := payload["transport"].(map[string]any)
	if transport["operator_confirmation_required"] != true {
		t.Fatalf("expected operator confirmation requirement, got %v", transport)
	}
	if _, ok := payload["planned_import_summary"].([]any); !ok {
		t.Fatalf("expected planned import summary, got %v", payload["planned_import_summary"])
	}
	if payload["support_tier"] != profiles.SupportTierFirstClassShipped {
		t.Fatalf("expected first-class doctor support tier, got %v", payload["support_tier"])
	}
}

func TestBootstrapCommandErrors(t *testing.T) {
	lockAppSeams(t)

	if err := bootstrapCommand(context.Background(), nil, new(bytes.Buffer)); err == nil {
		t.Fatal("expected usage error")
	}
	if err := bootstrapCommand(context.Background(), []string{"--bad"}, new(bytes.Buffer)); err == nil {
		t.Fatal("expected parse error")
	}
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "")
	if err := bootstrapCommand(context.Background(), []string{"--profile", "claude-code"}, new(bytes.Buffer)); err == nil {
		t.Fatal("expected missing password error for uninitialized vault")
	}
	if err := bootstrapCommand(context.Background(), []string{"--profile", "missing"}, new(bytes.Buffer)); err == nil {
		t.Fatal("expected missing profile error")
	}
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	var fixtureOut bytes.Buffer
	if err := bootstrapCommand(context.Background(), []string{"--json", "--profile", "codex-cli", "--project-root", projectRoot, "--hooks=false", "--verify=false"}, &fixtureOut); err != nil {
		t.Fatalf("bootstrap verify false: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(fixtureOut.Bytes(), &payload); err != nil {
		t.Fatalf("decode bootstrap output: %v", err)
	}
	if payload["verification"].(map[string]any)["ready"] != false {
		t.Fatalf("expected ready=false when verification disabled, got %v", payload["verification"])
	}

	origNewStore := newVaultStoreFn
	defer func() { newVaultStoreFn = origNewStore }()
	newVaultStoreFn = func() (*store.Store, error) { return nil, errors.New("store fail") }
	if err := bootstrapCommand(context.Background(), []string{"--profile", "claude-code"}, new(bytes.Buffer)); err == nil || !strings.Contains(err.Error(), "store fail") {
		t.Fatalf("expected store failure, got %v", err)
	}
}

func TestBootstrapCommandResidualFailures(t *testing.T) {
	lockAppSeams(t)

	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	installHookProject := t.TempDir()
	if out, err := run("git", "-C", installHookProject, "init"); err != nil {
		t.Fatalf("git init hook project: %v: %s", err, out)
	}
	origInstallHooks := installHooksFn
	installHooksFn = func(string) error { return errors.New("hook fail") }
	defer func() { installHooksFn = origInstallHooks }()
	if err := bootstrapCommand(context.Background(), []string{"--profile", "claude-code", "--project-root", installHookProject}, io.Discard); err == nil || !strings.Contains(err.Error(), "hook fail") {
		t.Fatalf("expected hook install failure, got %v", err)
	}

	aliasProject := t.TempDir()
	if out, err := run("git", "-C", aliasProject, "init"); err != nil {
		t.Fatalf("git init alias project: %v: %s", err, out)
	}
	if err := bootstrapCommand(context.Background(), []string{"--profile", "claude-code", "--project-root", aliasProject, "--hooks=false", "--bind-item", "missing"}, io.Discard); err == nil {
		t.Fatal("expected missing bind item failure")
	}

	manifestProject := t.TempDir()
	if out, err := run("git", "-C", manifestProject, "init"); err != nil {
		t.Fatalf("git init manifest project: %v: %s", err, out)
	}
	manifestPath := filepath.Join(manifestProject, ".hasp.manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{"version":"1","references":[{"alias":"secret_77","item":"missing_item"}]}`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := bootstrapCommand(context.Background(), []string{"--profile", "claude-code", "--project-root", manifestProject, "--hooks=false"}, io.Discard); err == nil {
		t.Fatal("expected resolve binding view failure")
	}

	verifyProject := t.TempDir()
	if out, err := run("git", "-C", verifyProject, "init"); err != nil {
		t.Fatalf("git init verify project: %v: %s", err, out)
	}
	if err := bootstrapCommandWithInput(context.Background(), []string{"--profile", "claude-code", "--project-root", verifyProject, "--hooks=false"}, bytes.NewBuffer(nil), io.Discard, func(profiles.Profile, bool) (map[string]any, error) {
		return nil, errors.New("verify fail")
	}); err == nil || !strings.Contains(err.Error(), "verify fail") {
		t.Fatalf("expected injected verification failure, got %v", err)
	}
}

func TestEnsureBootstrapHandleAndVerificationHelpers(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	vaultStore, err := newVaultStoreFn()
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	handle, state, err := ensureBootstrapHandle(context.Background(), vaultStore, false)
	if err != nil {
		t.Fatalf("ensure bootstrap handle: %v", err)
	}
	if state != "created" || handle == nil {
		t.Fatalf("unexpected handle state %q handle=%v", state, handle)
	}
	handle, state, err = ensureBootstrapHandle(context.Background(), vaultStore, false)
	if err != nil {
		t.Fatalf("ensure existing bootstrap handle: %v", err)
	}
	if state != "existing" || handle == nil {
		t.Fatalf("unexpected existing state %q handle=%v", state, handle)
	}

	origOpenVault := openVaultHandleFn
	defer func() { openVaultHandleFn = origOpenVault }()
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault fail") }
	if _, _, err := ensureBootstrapHandle(context.Background(), vaultStore, false); err == nil || !strings.Contains(err.Error(), "vault fail") {
		t.Fatalf("expected non-vault error, got %v", err)
	}

	verifyFalse, err := bootstrapVerification(profiles.Profile{Command: []string{"hasp", "mcp"}}, false)
	if err != nil || verifyFalse["ready"] != false {
		t.Fatalf("unexpected verify=false result: %v err=%v", verifyFalse, err)
	}
	verifyOther, err := bootstrapVerification(profiles.Profile{Command: []string{"custom-cli"}}, true)
	if err != nil || verifyOther["ready"] != true {
		t.Fatalf("unexpected non-mcp verification result: %v err=%v", verifyOther, err)
	}
	verifyEmpty, err := bootstrapVerificationWith(profiles.Profile{}, true, func() []string { return nil })
	if err != nil || verifyEmpty["ready"] != false {
		t.Fatalf("unexpected empty-command verification result: %v err=%v", verifyEmpty, err)
	}
	if _, err := bootstrapVerificationWith(profiles.Profile{Command: []string{"hasp", "mcp"}}, true, func() []string { return nil }); err == nil || !strings.Contains(err.Error(), "tool catalog is empty") {
		t.Fatalf("expected mcp tool catalog failure, got %v", err)
	}

	profile, gate, err := loadBootstrapProfile("claude-code", profiles.LoadProfile, profiles.ReleaseGateForProfile)
	if err != nil || profile.ID != "claude-code" || len(gate.EvalTests) == 0 {
		t.Fatalf("unexpected bootstrap profile load: profile=%+v gate=%+v err=%v", profile, gate, err)
	}
	if _, _, err := loadBootstrapProfile("claude-code", func(string) (profiles.Profile, error) {
		return profiles.Profile{}, errors.New("profile fail")
	}, profiles.ReleaseGateForProfile); err == nil || !strings.Contains(err.Error(), "profile fail") {
		t.Fatalf("expected profile loader failure, got %v", err)
	}
	if _, _, err := loadBootstrapProfile("claude-code", profiles.LoadProfile, func(string) (profiles.ReleaseGate, error) {
		return profiles.ReleaseGate{}, errors.New("gate fail")
	}); err == nil || !strings.Contains(err.Error(), "gate fail") {
		t.Fatalf("expected gate loader failure, got %v", err)
	}

	listing, err := bootstrapProfileListing(profiles.LoadCatalog, profiles.LoadReleaseGates)
	if err != nil {
		t.Fatalf("bootstrap profile listing: %v", err)
	}
	if len(listing["profiles"].([]map[string]any)) == 0 {
		t.Fatalf("expected profile listing entries, got %v", listing)
	}
	if _, err := bootstrapProfileListing(func() ([]profiles.Profile, error) {
		return nil, errors.New("catalog fail")
	}, profiles.LoadReleaseGates); err == nil || !strings.Contains(err.Error(), "catalog fail") {
		t.Fatalf("expected catalog failure, got %v", err)
	}
	if _, err := bootstrapProfileListing(profiles.LoadCatalog, func() (profiles.ReleaseGateManifest, error) {
		return profiles.ReleaseGateManifest{}, errors.New("manifest fail")
	}); err == nil || !strings.Contains(err.Error(), "manifest fail") {
		t.Fatalf("expected release gate failure, got %v", err)
	}
	if err := bootstrapProfilesCommandWith(failingBootstrapWriter{err: errors.New("encode fail")}, profiles.LoadCatalog, profiles.LoadReleaseGates); err == nil || !strings.Contains(err.Error(), "encode fail") {
		t.Fatalf("expected profile command encode failure, got %v", err)
	}
	if err := bootstrapProfilesCommandWith(io.Discard, func() ([]profiles.Profile, error) {
		return nil, errors.New("catalog fail")
	}, profiles.LoadReleaseGates); err == nil || !strings.Contains(err.Error(), "catalog fail") {
		t.Fatalf("expected wrapper catalog failure, got %v", err)
	}
}

func TestEnsureBootstrapHandleResidualFailures(t *testing.T) {
	lockAppSeams(t)

	origOpenVault := openVaultHandleFn
	origOpenStore := openStoreWithPasswordFn
	defer func() {
		openVaultHandleFn = origOpenVault
		openStoreWithPasswordFn = origOpenStore
	}()

	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	initHome := t.TempDir()
	t.Setenv("HASP_HOME", initHome)
	vaultStore, err := store.New(nil)
	if err != nil {
		t.Fatalf("new store for init failure: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("seed initialized store: %v", err)
	}
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, store.ErrVaultNotInitialized }
	if _, _, err := ensureBootstrapHandle(context.Background(), vaultStore, false); err == nil || !errors.Is(err, store.ErrVaultExists) {
		t.Fatalf("expected init failure from existing vault, got %v", err)
	}

	openHome := t.TempDir()
	t.Setenv("HASP_HOME", openHome)
	openStoreWithPasswordFn = func(context.Context, *store.Store, string) (*store.Handle, error) {
		return nil, errors.New("open fail")
	}
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, store.ErrVaultNotInitialized }
	vaultStore, err = store.New(nil)
	if err != nil {
		t.Fatalf("new store for open failure: %v", err)
	}
	if _, _, err := ensureBootstrapHandle(context.Background(), vaultStore, false); err == nil || !strings.Contains(err.Error(), "open fail") {
		t.Fatalf("expected open store failure, got %v", err)
	}
}

func TestImportCommandPreviewFromStdin(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	var out bytes.Buffer
	if err := importCommandWithInput(
		context.Background(),
		[]string{"--json", "--preview", "--format", "env", "-"},
		bytes.NewBufferString("export API_TOKEN=abc123\n"),
		&out,
	); err != nil {
		t.Fatalf("import preview from stdin: %v", err)
	}
	raw := out.String()
	if strings.Contains(raw, "abc123") {
		t.Fatalf("preview leaked imported value: %s", raw)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode import preview output: %v", err)
	}
	if payload["applied"] != false {
		t.Fatalf("expected preview-only import to report applied=false: %v", payload)
	}
	preview := payload["preview"].(map[string]any)
	if preview["capture_mode_label"] != "local-import-stdin" || preview["local_hygiene_path"] != true {
		t.Fatalf("unexpected stdin preview metadata: %+v", preview)
	}
}

func TestBootstrapDoctorSeparatesChecksAndSanitizesImportSummary(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	importPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(importPath, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write import file: %v", err)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	var out bytes.Buffer
	if err := bootstrapDoctorCommand(context.Background(), []string{"--json", "--profile", "claude-code", "--project-root", projectRoot, "--import", importPath}, bytes.NewBuffer(nil), &out); err != nil {
		t.Fatalf("bootstrap doctor: %v", err)
	}
	raw := out.String()
	if strings.Contains(raw, "API_TOKEN") || strings.Contains(raw, "abc123") {
		t.Fatalf("doctor output leaked import detail: %s", raw)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode bootstrap doctor output: %v", err)
	}
	if payload["support_tier"] != profiles.SupportTierFirstClassShipped {
		t.Fatalf("unexpected support tier: %v", payload)
	}
	checks := payload["checks"].(map[string]any)
	for _, key := range []string{"master_password", "project_root", "vault", "release_gate"} {
		if _, ok := checks[key]; !ok {
			t.Fatalf("expected doctor check %q in %v", key, checks)
		}
	}
	genericPath := payload["generic_path"].(map[string]any)
	if genericPath["first_class"] != false || genericPath["compatibility_label"] != profiles.CompatibilityLabelGeneric {
		t.Fatalf("unexpected generic path metadata: %+v", genericPath)
	}
	convenience := payload["convenience_mode"].(map[string]any)
	if convenience["compatibility_label"] != profiles.CompatibilityLabelConvenience {
		t.Fatalf("unexpected convenience metadata: %+v", convenience)
	}
	summary := payload["planned_import_summary"].([]any)
	if len(summary) != 1 {
		t.Fatalf("expected one planned import summary: %+v", payload)
	}
}

func BenchmarkBootstrapCommand(b *testing.B) {
	homeDir := b.TempDir()
	projectRoot := filepath.Join(b.TempDir(), "repo")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		b.Fatalf("mkdir project root: %v", err)
	}
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		b.Fatalf("git init: %v: %s", err, out)
	}
	b.Setenv("HASP_HOME", homeDir)
	b.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := bootstrapCommand(context.Background(), []string{"--profile", "claude-code", "--project-root", projectRoot, "--hooks=false"}, new(bytes.Buffer)); err != nil {
		b.Fatalf("bootstrap setup: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := bootstrapCommand(context.Background(), []string{"--profile", "claude-code", "--project-root", projectRoot, "--hooks=false", "--verify=false"}, new(bytes.Buffer)); err != nil {
			b.Fatalf("bootstrap command: %v", err)
		}
	}
}
