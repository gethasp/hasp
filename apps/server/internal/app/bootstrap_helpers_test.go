package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/profiles"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestBootstrapOptionAndHelperCoverage(t *testing.T) {
	if _, err := parseBootstrapOptions(nil, false); err == nil {
		t.Fatal("expected missing profile usage error")
	}
	if _, err := parseBootstrapOptions([]string{"--profile", "claude-code", "--import"}, false); err == nil {
		t.Fatal("expected missing import flag value error")
	}
	if _, err := parseBootstrapOptions([]string{"--profile", "claude-code"}, true); err == nil {
		t.Fatal("expected generic bootstrap profile rejection")
	}
	opts, err := parseBootstrapOptions([]string{"--profile", "claude-code", "--import", "-", "--import=service.json", "--bind-imports", "--hooks=false"}, false)
	if err != nil {
		t.Fatalf("parse bootstrap options: %v", err)
	}
	if len(opts.ImportPaths) != 2 || opts.ImportPaths[0] != "-" || opts.ImportPaths[1] != "service.json" || !opts.BindImports || opts.InstallHooks {
		t.Fatalf("unexpected parsed options: %+v", opts)
	}
	if _, _, err := extractStringListFlag([]string{"--import"}, "--import"); err == nil {
		t.Fatal("expected missing string-list value error")
	}

	proof := summarizeProof(map[string]profiles.SupportCheck{
		"warn": {Status: "warn"},
		"fail": {Status: "fail"},
	})
	if proof.Status != "fail" || !strings.Contains(proof.Recovery, "first-class") {
		t.Fatalf("unexpected summarized proof: %+v", proof)
	}
	if !bootstrapHookPresent(t.TempDir()) {
		gitRoot := t.TempDir()
		if out, err := run("git", "-C", gitRoot, "init"); err != nil {
			t.Fatalf("git init: %v: %s", err, out)
		}
		if err := os.MkdirAll(filepath.Join(gitRoot, ".git", "hooks"), 0o755); err != nil {
			t.Fatalf("mkdir hooks: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gitRoot, ".git", "hooks", "pre-commit"), []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatalf("write hook: %v", err)
		}
		if !bootstrapHookPresent(gitRoot) {
			t.Fatal("expected bootstrapHookPresent to detect hook")
		}
	}

	var out bytes.Buffer
	if err := bootstrapCommandWith(context.Background(), []string{"profiles"}, &out, bootstrapVerification); err != nil {
		t.Fatalf("bootstrapCommandWith wrapper: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("expected wrapper output")
	}
	if err := bootstrapGenericCommand(context.Background(), []string{"--profile", "claude-code"}, bytes.NewBuffer(nil), io.Discard, bootstrapVerification); err == nil {
		t.Fatal("expected generic command profile rejection")
	}
	if err := bootstrapDoctorCommand(context.Background(), []string{"generic", "--bad"}, bytes.NewBuffer(nil), io.Discard); err == nil {
		t.Fatal("expected bootstrap doctor parse error")
	}
	if err := bootstrapDoctorCommand(context.Background(), []string{"--profile", "missing"}, bytes.NewBuffer(nil), io.Discard); err == nil {
		t.Fatal("expected bootstrap doctor missing profile error")
	}
}

func TestBootstrapPreviewHelpers(t *testing.T) {
	lockAppSeams(t)

	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "")
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	aliases, binding, visible, err := bootstrapAliasContext(context.Background(), projectRoot)
	if err != nil {
		t.Fatalf("bootstrap alias context without vault: %v", err)
	}
	if len(aliases) != 0 || len(binding.Aliases) != 0 || len(visible) != 0 {
		t.Fatalf("expected empty preview context, got aliases=%v binding=%+v visible=%v", aliases, binding, visible)
	}

	origOpenVault := openVaultHandleFn
	defer func() { openVaultHandleFn = origOpenVault }()
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault fail") }
	if _, _, err := previewBootstrapHandle(context.Background()); err == nil || !strings.Contains(err.Error(), "vault fail") {
		t.Fatalf("expected preview handle error, got %v", err)
	}
	if _, _, _, err := bootstrapAliasContext(context.Background(), projectRoot); err == nil || !strings.Contains(err.Error(), "vault fail") {
		t.Fatalf("expected bootstrapAliasContext preview failure, got %v", err)
	}
	openVaultHandleFn = origOpenVault

	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}
	aliases, _, visible, err = bootstrapAliasContext(context.Background(), projectRoot)
	if err != nil {
		t.Fatalf("bootstrap alias context with vault: %v", err)
	}
	if aliases["secret_01"] != "api_token" || len(visible) != 1 {
		t.Fatalf("unexpected populated alias context: aliases=%v visible=%v", aliases, visible)
	}
	if bootstrapHookPresent("") {
		t.Fatal("expected empty project root to have no hook")
	}

	manifestPath := filepath.Join(projectRoot, ".hasp.manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{"version":"1","references":[{"alias":"secret_99","item":"missing_item"}]}`), 0o600); err != nil {
		t.Fatalf("write malformed manifest: %v", err)
	}
	if _, _, _, err := bootstrapAliasContext(context.Background(), projectRoot); err == nil {
		t.Fatal("expected bootstrapAliasContext manifest failure")
	}

	t.Setenv("HASP_HOME", t.TempDir())
	if aliases, _, _, err := bootstrapAliasContext(context.Background(), projectRoot); err != nil || len(aliases) != 0 {
		t.Fatalf("expected nil-handle bootstrapAliasContext, got aliases=%v err=%v", aliases, err)
	}
}

func TestBootstrapErrorSeams(t *testing.T) {
	lockAppSeams(t)

	origCanonical := bootstrapCanonicalProjectRootFn
	origResolveBinding := resolveBindingViewBootstrapFn
	origOpenVault := openVaultHandleFn
	defer func() {
		bootstrapCanonicalProjectRootFn = origCanonical
		resolveBindingViewBootstrapFn = origResolveBinding
		openVaultHandleFn = origOpenVault
	}()

	bootstrapCanonicalProjectRootFn = func(context.Context, string) (string, error) {
		return "", errors.New("canonical fail")
	}
	if _, err := buildBootstrapDoctor(context.Background(), genericBootstrapTarget(), bootstrapOptions{ProjectRoot: "."}, bytes.NewBuffer(nil)); err == nil || !strings.Contains(err.Error(), "canonical fail") {
		t.Fatalf("expected canonical root failure, got %v", err)
	}
	bootstrapCanonicalProjectRootFn = origCanonical

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

	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault fail") }
	if err := bootstrapDoctorCommand(context.Background(), []string{"--profile", "claude-code", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "vault fail") {
		t.Fatalf("expected doctor preview failure, got %v", err)
	}
	openVaultHandleFn = origOpenVault

	resolveBindingViewBootstrapFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("binding fail")
	}
	if err := bootstrapCommand(context.Background(), []string{"--profile", "claude-code", "--project-root", projectRoot, "--import", filepath.Join(t.TempDir(), "missing.env")}, io.Discard); err == nil || !strings.Contains(err.Error(), "binding fail") {
		t.Fatalf("expected bootstrap binding failure, got %v", err)
	}
	if err := bootstrapDoctorCommand(context.Background(), []string{"--profile", "claude-code", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "binding fail") {
		t.Fatalf("expected doctor binding failure, got %v", err)
	}
}

func TestBootstrapExecutionAndDoctorResidualErrors(t *testing.T) {
	lockAppSeams(t)

	origResolveBinding := resolveBindingViewBootstrapFn
	origCanonical := bootstrapCanonicalProjectRootFn
	defer func() {
		resolveBindingViewBootstrapFn = origResolveBinding
		bootstrapCanonicalProjectRootFn = origCanonical
	}()

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
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}

	target := genericBootstrapTarget()
	if err := executeBootstrap(context.Background(), target, bootstrapOptions{ProjectRoot: projectRoot, ImportPaths: []string{filepath.Join(t.TempDir(), "missing.env")}}, bytes.NewBuffer(nil), io.Discard, bootstrapVerification); err == nil {
		t.Fatal("expected executeBootstrap import preview failure")
	}

	callCount := 0
	resolveBindingViewBootstrapFn = func(handle *store.Handle, ctx context.Context, projectRoot string) (store.Binding, []store.VisibleReference, error) {
		callCount++
		if callCount >= 2 {
			return store.Binding{}, nil, errors.New("post-bind fail")
		}
		return origResolveBinding(handle, ctx, projectRoot)
	}
	if err := executeBootstrap(context.Background(), target, bootstrapOptions{ProjectRoot: projectRoot, BindItems: []string{"api_token"}}, bytes.NewBuffer(nil), io.Discard, bootstrapVerification); err == nil || !strings.Contains(err.Error(), "post-bind fail") {
		t.Fatalf("expected executeBootstrap post-bind failure, got %v", err)
	}
	resolveBindingViewBootstrapFn = origResolveBinding

	if _, err := buildBootstrapDoctor(context.Background(), target, bootstrapOptions{ProjectRoot: projectRoot, ImportPaths: []string{filepath.Join(t.TempDir(), "missing.env")}}, bytes.NewBuffer(nil)); err == nil {
		t.Fatal("expected doctor import preview failure")
	}
	if _, err := buildBootstrapDoctor(context.Background(), target, bootstrapOptions{ProjectRoot: projectRoot, BindItems: []string{"missing"}}, bytes.NewBuffer(nil)); err == nil {
		t.Fatal("expected doctor missing bind item failure")
	}

	t.Setenv("HASP_HOME", t.TempDir())
	report, err := buildBootstrapDoctor(context.Background(), target, bootstrapOptions{ProjectRoot: projectRoot, BindItems: []string{"missing"}}, bytes.NewBuffer(nil))
	if err != nil {
		t.Fatalf("doctor planned bind count without vault: %v", err)
	}
	if report.PlannedBindCount != 1 {
		t.Fatalf("expected planned bind count, got %+v", report)
	}

	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "")
	report, err = buildBootstrapDoctor(context.Background(), target, bootstrapOptions{ProjectRoot: projectRoot}, bytes.NewBuffer(nil))
	if err != nil {
		t.Fatalf("doctor without master password: %v", err)
	}
	if report.Checks["master_password"].Status != "fail" {
		t.Fatalf("expected missing master password check to fail: %+v", report.Checks)
	}
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	bootstrapCanonicalProjectRootFn = func(context.Context, string) (string, error) {
		return "", errors.New("canonical fail")
	}
	if _, err := buildBootstrapDoctor(context.Background(), target, bootstrapOptions{ProjectRoot: projectRoot}, bytes.NewBuffer(nil)); err == nil || !strings.Contains(err.Error(), "canonical fail") {
		t.Fatalf("expected canonical project root failure, got %v", err)
	}

	if proof := summarizeProof(map[string]profiles.SupportCheck{"warn": {Status: "warn"}}); proof.Status != "warn" {
		t.Fatalf("expected warn-only summarized proof, got %+v", proof)
	}
}

func TestBootstrapProfileListingDowngradesBrokenProof(t *testing.T) {
	profile := profiles.Profile{
		ID:                   "broken",
		Name:                 "Broken",
		Transport:            "mcp-stdio",
		Command:              []string{"hasp", "mcp"},
		ProjectBindingRecipe: "bind",
		ApprovalPath:         "approve",
		SafeInjectPath:       "safe",
		WriteEnvPath:         "write-env",
		RegressionFixture:    "does/not/exist.json",
		DocsPath:             "docs/agent-profiles/README.md",
	}
	listing, err := bootstrapProfileListing(func() ([]profiles.Profile, error) {
		return []profiles.Profile{profile}, nil
	}, func() (profiles.ReleaseGateManifest, error) {
		return profiles.ReleaseGateManifest{
			RequiredDocSections: []string{"## Missing"},
			Profiles:            map[string]profiles.ReleaseGate{"broken": {}},
		}, nil
	})
	if err != nil {
		t.Fatalf("bootstrapProfileListing downgrade: %v", err)
	}
	first := listing["profiles"].([]map[string]any)[0]
	if first["support_tier"] != profiles.SupportTierGenericCompatible || first["first_class"] != false {
		t.Fatalf("expected downgraded support tier, got %v", first)
	}
}
