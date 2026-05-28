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
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestProjectTargetCommandAndHelperCoverage(t *testing.T) {
	lockAppSeams(t)
	origOpen := openVaultHandleFn
	t.Cleanup(func() { openVaultHandleFn = origOpen })
	projectRoot, _, _ := setupProjectTargetManifestFixture(t)
	unmanagedExample := filepath.Join(projectRoot, "apps", "server", ".env.example")
	if err := os.WriteFile(unmanagedExample, []byte("HAND_AUTHORED=1\n"), 0o600); err != nil {
		t.Fatalf("write unmanaged example: %v", err)
	}
	_ = projectExamplesCommand(context.Background(), []string{"--project-root", projectRoot, "--target", "server.dev", "--write"}, io.Discard)

	for _, args := range [][]string{
		{"--bad"},
		{"--project-root", projectRoot, "extra"},
		{"--project-root", "~other/project"},
		{"--project-root", filepath.Join(t.TempDir(), "missing")},
		{"--project-root", projectRoot, "--target", "missing"},
	} {
		_ = projectRequirementsCommand(context.Background(), args, io.Discard)
	}
	for _, args := range [][]string{
		{"--bad"},
		{"--project-root", projectRoot, "extra"},
		{"--project-root", filepath.Join(t.TempDir(), "missing")},
	} {
		_ = projectTargetsCommand(context.Background(), args, io.Discard)
	}
	for _, args := range [][]string{
		{"--bad"},
		{"--project-root", projectRoot, "extra"},
		{"--project-root", projectRoot},
		{"--project-root", projectRoot, "--check", "--write"},
		{"--project-root", filepath.Join(t.TempDir(), "missing"), "--check"},
		{"--project-root", projectRoot, "--target", "missing", "--check"},
	} {
		_ = projectExamplesCommand(context.Background(), args, io.Discard)
	}
	for _, args := range [][]string{
		{"--bad"},
		{"--project-root", projectRoot, "extra"},
		{"--project-root", filepath.Join(t.TempDir(), "missing")},
	} {
		_ = projectManifestDoctorCommand(context.Background(), args, io.Discard)
	}

	var out bytes.Buffer
	if err := projectRequirementsCommand(context.Background(), []string{"--project-root", projectRoot}, &out); err != nil {
		t.Fatalf("requirements human: %v", err)
	}
	out.Reset()
	if err := projectTargetsCommand(context.Background(), []string{"--project-root", projectRoot}, &out); err != nil {
		t.Fatalf("targets human: %v", err)
	}
	out.Reset()
	if err := projectExamplesCommand(context.Background(), []string{"--project-root", projectRoot, "--target", "server.dev", "--check"}, &out); err != nil {
		t.Fatalf("examples human: %v", err)
	}
	out.Reset()
	if err := projectManifestDoctorCommand(context.Background(), []string{"--project-root", projectRoot}, &out); err != nil {
		t.Fatalf("doctor human: %v", err)
	}

	manifest := projectCoverageManifest()
	if _, err := selectedManifestTargets(manifest, "missing"); err == nil {
		t.Fatal("expected unknown selected target")
	}
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault closed") }
	views, err := projectRequirementViews(context.Background(), projectRoot, manifest, "server.dev")
	if err != nil {
		t.Fatalf("requirement views without vault: %v", err)
	}
	if len(views) == 0 {
		t.Fatal("expected requirement views")
	}
	present, exposed := projectRequirementState(context.Background(), nil, projectRoot, "secret_01", "OPENAI_API_KEY", true)
	if present || exposed {
		t.Fatal("nil handle should report absent/unexposed")
	}
	if got := projectRequirementSuggestion(store.ManifestRequirement{Kind: store.ItemKindFile}, "SERVICE_ACCOUNT", true, false); !strings.Contains(got, "--kind file") {
		t.Fatalf("file suggestion = %q", got)
	}
	if got := projectRequirementSuggestion(store.ManifestRequirement{Kind: store.ItemKindKV}, "API_KEY", false, false); got != "" {
		t.Fatalf("suggestion without item name = %q", got)
	}
	if got := projectRequirementSuggestion(store.ManifestRequirement{Kind: store.ItemKindKV}, "API_KEY", true, true); got != "" {
		t.Fatalf("suggestion for present item = %q", got)
	}
	targets := projectTargetViews(manifest)
	if len(targets) == 0 || !targets[0].HasEnv {
		t.Fatalf("target views = %+v", targets)
	}
}

func TestProjectManifestAuthoringCommandCoverage(t *testing.T) {
	lockAppSeams(t)
	origOpen := openVaultHandleFn
	origRead := appReadFileFn
	origWrite := appWriteFileFn
	origRecord := recordManifestReviewFn
	t.Cleanup(func() {
		openVaultHandleFn = origOpen
		appReadFileFn = origRead
		appWriteFileFn = origWrite
		recordManifestReviewFn = origRecord
	})

	ctx := context.Background()
	projectRoot := t.TempDir()
	fileRoot := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fileRoot, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file root: %v", err)
	}

	for _, args := range [][]string{
		{"init", "--bad"},
		{"init", "--project-root", projectRoot, "extra"},
		{"init", "--project-root", "~other/project"},
		{"init", "--project-root", fileRoot},
	} {
		_ = projectCommandWithStderr(ctx, args, io.Discard, io.Discard)
	}

	var out bytes.Buffer
	if err := projectCommandWithStderr(ctx, []string{"init", "--project-root", projectRoot, "--name", "Demo", "--description", "desc"}, &out, io.Discard); err != nil {
		t.Fatalf("project init: %v", err)
	}
	if err := projectManifestInitCommand(ctx, []string{"--project-root", projectRoot}, io.Discard); err == nil {
		t.Fatal("expected duplicate manifest error")
	}

	readErrRoot := t.TempDir()
	appReadFileFn = func(string) ([]byte, error) { return nil, errors.New("read manifest fail") }
	if err := projectManifestInitCommand(ctx, []string{"--project-root", readErrRoot}, io.Discard); err == nil {
		t.Fatal("expected manifest read error")
	}
	appReadFileFn = origRead

	writeErrRoot := t.TempDir()
	appWriteFileFn = func(string, []byte, os.FileMode) error { return errors.New("write manifest fail") }
	if err := projectManifestInitCommand(ctx, []string{"--project-root", writeErrRoot}, io.Discard); err == nil {
		t.Fatal("expected manifest write error")
	}
	appWriteFileFn = origWrite

	for _, args := range [][]string{
		nil,
		{"unknown"},
	} {
		_ = projectTargetCommand(ctx, args, io.Discard)
	}
	for _, args := range [][]string{
		nil,
		{"server.dev", "--bad"},
		{"server.dev", "--project-root", projectRoot},
		{"server.dev", "--project-root", fileRoot, "--env", "TOKEN=@TOKEN"},
		{"bad.ref", "--project-root", projectRoot, "--env", "TOKEN=TOKEN"},
	} {
		_ = projectTargetAddCommand(ctx, args, io.Discard)
	}

	if err := templateCommand(ctx, nil, io.Discard); err != nil {
		t.Fatalf("template help: %v", err)
	}
	if err := templateCommand(ctx, []string{"init", "--project-root", t.TempDir()}, io.Discard); err != nil {
		t.Fatalf("template init: %v", err)
	}
	sortRoot := t.TempDir()
	if err := projectTargetAddCommand(ctx, []string{"sort.env", "--project-root", sortRoot, "--env", "B=@B", "--env", "A=@A"}, io.Discard); err != nil {
		t.Fatalf("target add with sorted env refs: %v", err)
	}
	if err := templateCommand(ctx, []string{"add", "server.dev", "--project-root", projectRoot, "--description", "Local dev", "--env", "TOKEN=@TOKEN", "--file", "CONFIG=@CONFIG_FILE", "--env-example", ".env.example", "--", "sh", "-c", "true"}, &out); err != nil {
		t.Fatalf("template add: %v", err)
	}
	if err := templateCommand(ctx, []string{"add", "server.dev", "--project-root", projectRoot, "--env", "OTHER=@OTHER"}, io.Discard); err == nil {
		t.Fatal("expected duplicate target error")
	}
	if err := templateCommand(ctx, []string{"add", "kind.bad", "--project-root", projectRoot, "--file", "TOKEN_FILE=@TOKEN"}, io.Discard); err == nil {
		t.Fatal("expected requirement kind mismatch")
	}
	missingRoot := filepath.Join(t.TempDir(), "missing")
	if err := projectTargetAddCommand(ctx, []string{"missing.root", "--project-root", missingRoot, "--env", "TOKEN=@TOKEN"}, io.Discard); err == nil {
		t.Fatal("expected missing project root error")
	}
	badAddRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(badAddRoot, ".hasp.manifest.json"), 0o700); err != nil {
		t.Fatalf("mkdir bad add manifest path: %v", err)
	}
	if err := projectTargetAddCommand(ctx, []string{"read.fail", "--project-root", badAddRoot, "--env", "TOKEN=@TOKEN"}, io.Discard); err == nil {
		t.Fatal("expected target add manifest read error")
	}
	writeFailRoot := t.TempDir()
	appWriteFileFn = func(string, []byte, os.FileMode) error { return errors.New("target add write fail") }
	if err := projectTargetAddCommand(ctx, []string{"write.fail", "--project-root", writeFailRoot, "--env", "TOKEN=@TOKEN"}, io.Discard); err == nil {
		t.Fatal("expected target add write failure")
	}
	appWriteFileFn = origWrite
	for _, args := range [][]string{
		{"list", "--project-root", projectRoot},
		{"ls", "--project-root", projectRoot},
		{"doctor", "--project-root", projectRoot},
		{"unknown"},
	} {
		_ = templateCommand(ctx, args, io.Discard)
	}

	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return &store.Handle{}, nil }
	reviewed := false
	recordManifestReviewFn = func(_ *store.Handle, root string, expansion store.ManifestTargetExpansion) error {
		reviewed = root == projectRoot && expansion.TargetName == "server.dev"
		return nil
	}
	if err := templateCommand(ctx, []string{"review", "server.dev", "--project-root", projectRoot}, &out); err != nil {
		t.Fatalf("template review: %v", err)
	}
	if !reviewed {
		t.Fatal("expected review to record manifest target")
	}
	recordManifestReviewFn = func(*store.Handle, string, store.ManifestTargetExpansion) error { return errors.New("record fail") }
	if err := projectTargetReviewCommand(ctx, []string{"server.dev", "--project-root", projectRoot}, io.Discard); err == nil {
		t.Fatal("expected review record failure")
	}
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault closed") }
	if err := projectTargetReviewCommand(ctx, []string{"server.dev", "--project-root", projectRoot}, io.Discard); err == nil {
		t.Fatal("expected review vault failure")
	}
	for _, args := range [][]string{
		nil,
		{"server.dev", "--bad"},
		{"server.dev", "--project-root", projectRoot, "extra"},
		{"server.dev", "--project-root", fileRoot},
		{"server.dev", "--project-root", t.TempDir()},
		{"missing", "--project-root", projectRoot},
	} {
		_ = projectTargetReviewCommand(ctx, args, io.Discard)
	}

	if _, _, err := loadProjectManifest(fileRoot); err == nil {
		t.Fatal("expected load manifest for file root to fail")
	}
	badManifestRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(badManifestRoot, ".hasp.manifest.json"), 0o700); err != nil {
		t.Fatalf("mkdir manifest path: %v", err)
	}
	if _, _, err := loadProjectManifest(badManifestRoot); err == nil {
		t.Fatal("expected manifest read failure")
	}
	if _, _, err := loadOrCreateProjectManifest(badManifestRoot); err == nil {
		t.Fatal("expected load-or-create manifest read failure")
	}
	if err := writeProjectManifest(t.TempDir(), store.RepoManifest{Version: "bad"}); err == nil {
		t.Fatal("expected manifest decode failure")
	}

	aliases := manifestAliasMap(store.RepoManifest{References: []store.ManifestReference{
		{Alias: " secret_01 ", Item: " TOKEN "},
		{Alias: "", Item: "skip"},
		{Alias: "skip", Item: ""},
	}})
	if aliases["secret_01"] != "TOKEN" || len(aliases) != 1 {
		t.Fatalf("aliases = %+v", aliases)
	}
	requirementManifest := store.RepoManifest{
		References:   []store.ManifestReference{{Alias: "secret_01", Item: "TOKEN"}},
		Requirements: []store.ManifestRequirement{{Ref: "@TOKEN", Kind: store.ItemKindKV}},
	}
	aliasMap := manifestAliasMap(requirementManifest)
	if err := ensureManifestRequirementForNamedRef(&requirementManifest, &aliasMap, "@TOKEN", store.ItemKindKV); err != nil {
		t.Fatalf("existing requirement: %v", err)
	}
	declaredManifest := store.RepoManifest{
		References: []store.ManifestReference{{Alias: "secret_01", Item: "TOKEN"}},
	}
	declaredAliases := manifestAliasMap(declaredManifest)
	if err := ensureManifestRequirementForNamedRef(&declaredManifest, &declaredAliases, "@TOKEN", store.ItemKindKV); err != nil {
		t.Fatalf("declared reference requirement: %v", err)
	}
	if err := ensureManifestRequirementForNamedRef(&requirementManifest, &aliasMap, "@TOKEN", store.ItemKindFile); err == nil {
		t.Fatal("expected existing requirement kind mismatch")
	}
	for _, ref := range []string{"", "TOKEN", "@", "@BAD REF"} {
		if item, ok := manifestItemNameFromNamedRef(ref); ok || item != "" {
			t.Fatalf("invalid ref %q produced %q/%v", ref, item, ok)
		}
	}

	renderResults := []projectManifestWriteResult{
		{ProjectRoot: projectRoot, ManifestPath: filepath.Join(projectRoot, ".hasp.manifest.json"), Created: true},
		{ProjectRoot: projectRoot, ManifestPath: filepath.Join(projectRoot, ".hasp.manifest.json"), Updated: true, Target: "server.dev", Refs: []string{"@TOKEN"}, Command: true},
	}
	for _, result := range renderResults {
		for allow := 0; allow < 12; allow++ {
			_ = renderProjectManifestWriteResult(&nthWriteErrWriter{allow: allow}, "title", "lead", result)
		}
		_ = renderProjectManifestWriteResult(matchErrWriter{match: "hasp project doctor"}, "title", "lead", result)
		if err := renderProjectManifestWriteResult(io.Discard, "title", "lead", result); err != nil {
			t.Fatalf("render manifest result: %v", err)
		}
	}
}

func TestProjectExampleActionCoverage(t *testing.T) {
	lockAppSeams(t)
	origRead := appReadFileFn
	origMkdir := appMkdirAllFn
	origWrite := appWriteFileFn
	t.Cleanup(func() {
		appReadFileFn = origRead
		appMkdirAllFn = origMkdir
		appWriteFileFn = origWrite
	})
	projectRoot := t.TempDir()
	manifest := projectCoverageManifest()
	manifest.Targets[0].Delivery = manifest.Targets[0].Delivery[:4]
	targets := manifest.Targets[:1]

	results, err := projectExampleActions(projectRoot, manifest, targets, true)
	if err != nil {
		t.Fatalf("write missing examples: %v", err)
	}
	if len(results) != 2 || !results[0].Written {
		t.Fatalf("unexpected missing write results: %+v", results)
	}
	results, err = projectExampleActions(projectRoot, manifest, targets, false)
	if err != nil {
		t.Fatalf("check existing examples: %v", err)
	}
	if len(results) != 2 || results[0].Missing || results[0].Stale {
		t.Fatalf("unexpected check results: %+v", results)
	}

	envPath := filepath.Join(projectRoot, "apps", "server", ".env.example")
	if err := os.WriteFile(envPath, []byte("# "+projectExampleGeneratedMarker+"\nSTALE=1\n"), 0o600); err != nil {
		t.Fatalf("write stale generated env: %v", err)
	}
	results, err = projectExampleActions(projectRoot, manifest, targets, true)
	if err != nil {
		t.Fatalf("rewrite stale generated example: %v", err)
	}
	if !results[0].Written {
		t.Fatalf("expected stale generated rewrite: %+v", results)
	}
	if err := os.WriteFile(envPath, []byte("HAND_AUTHORED=1\n"), 0o600); err != nil {
		t.Fatalf("write unmanaged env: %v", err)
	}
	if _, err := projectExampleActions(projectRoot, manifest, targets, true); err == nil {
		t.Fatal("expected unmanaged overwrite refusal")
	}

	appReadFileFn = func(string) ([]byte, error) { return nil, errors.New("read fail") }
	if _, err := projectExampleActions(projectRoot, manifest, targets, false); err == nil {
		t.Fatal("expected read failure")
	}
	appReadFileFn = os.ReadFile
	appMkdirAllFn = func(string, os.FileMode) error { return errors.New("mkdir fail") }
	if _, err := projectExampleActions(t.TempDir(), manifest, targets, true); err == nil {
		t.Fatal("expected mkdir failure")
	}
	appMkdirAllFn = os.MkdirAll
	appWriteFileFn = func(string, []byte, os.FileMode) error { return errors.New("write fail") }
	if _, err := projectExampleActions(t.TempDir(), manifest, targets, true); err == nil {
		t.Fatal("expected write failure")
	}
	appWriteFileFn = os.WriteFile
	if err := os.WriteFile(envPath, []byte("# "+projectExampleGeneratedMarker+"\nSTALE=1\n"), 0o600); err != nil {
		t.Fatalf("write stale generated env again: %v", err)
	}
	appWriteFileFn = func(string, []byte, os.FileMode) error { return errors.New("rewrite fail") }
	if _, err := projectExampleActions(projectRoot, manifest, targets, true); err == nil {
		t.Fatal("expected stale rewrite failure")
	}
	appWriteFileFn = os.WriteFile

	badManifest := manifest
	badTarget := badManifest.Targets[0]
	badTarget.Delivery[0].Ref = "missing"
	badTarget.Delivery[3].Ref = "missing"
	if _, err := projectExampleActions(projectRoot, badManifest, []store.ManifestTarget{badTarget}, false); err == nil {
		t.Fatal("expected example action render error")
	}
	if _, err := renderProjectExample(badManifest, badTarget, badTarget.Examples[0]); err == nil {
		t.Fatal("expected env render error for unknown ref")
	}
	if _, err := renderProjectExample(badManifest, badTarget, badTarget.Examples[1]); err == nil {
		t.Fatal("expected xcconfig render error for unknown ref")
	}
	if _, err := renderProjectExample(badManifest, badTarget, store.ManifestExample{Format: "bad"}); err == nil {
		t.Fatal("expected unsupported example format")
	}
	if got := projectExamplePlaceholder(store.ManifestRequirement{Classification: store.ManifestClassificationPublicConfig}); got != projectExamplePublicValue {
		t.Fatalf("public placeholder = %q", got)
	}
	if got := projectExamplePlaceholder(store.ManifestRequirement{Kind: store.ItemKindFile}); got != projectExampleFileValue {
		t.Fatalf("file placeholder = %q", got)
	}
}

func TestProjectDoctorAndRenderCoverage(t *testing.T) {
	lockAppSeams(t)
	origOpen := openVaultHandleFn
	origRead := appReadFileFn
	t.Cleanup(func() {
		openVaultHandleFn = origOpen
		appReadFileFn = origRead
	})
	projectRoot := t.TempDir()
	manifest := projectCoverageManifest()
	manifest.Targets[0].Delivery = manifest.Targets[0].Delivery[:4]
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault closed") }
	appReadFileFn = func(path string) ([]byte, error) {
		switch {
		case strings.Contains(path, "unreadable"):
			return nil, errors.New("read fail")
		case strings.Contains(path, "stale"):
			return []byte("# " + projectExampleGeneratedMarker + "\nSTALE=1\n"), nil
		case strings.Contains(path, "ok"):
			data, err := renderProjectExample(manifest, manifest.Targets[0], manifest.Targets[0].Examples[0])
			if err != nil {
				t.Fatalf("render ok example: %v", err)
			}
			return data, nil
		default:
			return nil, os.ErrNotExist
		}
	}
	manifest.Targets[0].Examples = []store.ManifestExample{
		{Format: "env", Path: "missing.env"},
		{Format: "env", Path: "unreadable.env"},
		{Format: "env", Path: "stale.env"},
		{Format: "env", Path: "ok.env"},
	}
	invalidTarget := manifest.Targets[0]
	invalidTarget.Name = "invalid.example"
	invalidTarget.Delivery = append([]store.ManifestDelivery(nil), invalidTarget.Delivery...)
	invalidTarget.Delivery[0].Ref = "missing"
	invalidTarget.Examples = []store.ManifestExample{{Format: "env", Path: "invalid.env"}}
	manifest.Targets = append(manifest.Targets, invalidTarget)
	diagnostics := buildProjectDoctorDiagnostics(context.Background(), projectRoot, manifest)
	if len(diagnostics) == 0 {
		t.Fatal("expected diagnostics")
	}
	appReadFileFn = os.ReadFile
	openVaultHandleFn = openVaultHandle
	projectRoot2, _ := setupTargetRuntimeFixture(t)
	if err := Run(context.Background(), []string{"secret", "add", "--vault-only", "--from-stdin", "UNEXPOSED_SECRET"}, bytes.NewBufferString("value"), io.Discard, io.Discard); err != nil {
		t.Fatalf("add unexposed secret: %v", err)
	}
	manifest2 := store.RepoManifest{
		Version:    "v1",
		References: []store.ManifestReference{{Alias: "unexposed_01", Item: "UNEXPOSED_SECRET"}},
		Requirements: []store.ManifestRequirement{{
			Ref: "unexposed_01", Kind: store.ItemKindKV, Classification: store.ManifestClassificationSecret, Required: true,
		}},
	}
	openVaultHandleFn = openVaultHandle
	diagnostics = buildProjectDoctorDiagnostics(context.Background(), projectRoot2, manifest2)
	foundUnexposed := false
	for _, diag := range diagnostics {
		if diag.Code == "requirement_unexposed" {
			foundUnexposed = true
		}
	}
	if !foundUnexposed {
		t.Fatalf("expected unexposed diagnostic: %+v", diagnostics)
	}

	reqs := []projectRequirementView{{
		Ref: "secret_01", Kind: store.ItemKindKV, Classification: store.ManifestClassificationSecret,
		Required: true, Present: true, Exposed: true, VaultAvailable: true,
		Targets: []string{"server.dev"}, SuggestedCommand: "hasp secret add OPENAI_API_KEY",
	}, {Ref: "missing", Kind: store.ItemKindFile, Classification: store.ManifestClassificationSecret}}
	targets := []projectTargetView{{Name: "server.dev", Refs: []string{"secret_01"}, HasCommand: true, HasExamples: true}}
	results := []projectExampleResult{{Target: "written", Written: true}, {Target: "missing", Missing: true}, {Target: "stale", Stale: true}, {Target: "ok"}}
	doctor := []projectDoctorDiagnostic{{
		Code: "requirement_ok", Severity: "info", Ref: "secret_01", Kind: store.ItemKindKV,
		Classification: store.ManifestClassificationSecret, Present: true, Exposed: true,
	}, {Code: "target_drift", Severity: "warning", Target: "server.dev", Stale: true, Ignored: true}}

	renderers := []func(io.Writer) error{
		func(w io.Writer) error { return renderProjectRequirements(w, projectRoot, "server.dev", reqs) },
		func(w io.Writer) error { return renderProjectRequirements(w, projectRoot, "", nil) },
		func(w io.Writer) error { return renderProjectTargets(w, projectRoot, targets) },
		func(w io.Writer) error { return renderProjectTargets(w, projectRoot, nil) },
		func(w io.Writer) error { return renderProjectExamples(w, projectRoot, results, true) },
		func(w io.Writer) error { return renderProjectExamples(w, projectRoot, nil, false) },
		func(w io.Writer) error { return renderProjectDoctor(w, projectRoot, doctor) },
		func(w io.Writer) error { return renderProjectDoctor(w, projectRoot, nil) },
	}
	for _, render := range renderers {
		for allow := 0; allow < 40; allow++ {
			_ = render(&nthWriteErrWriter{allow: allow})
		}
		if err := render(io.Discard); err != nil {
			t.Fatalf("render success: %v", err)
		}
	}
	if got := doctorBindingFailureDetail(projectRoot, errors.New("plain failure")); !strings.Contains(got, "plain failure") {
		t.Fatalf("plain binding detail = %q", got)
	}
	classified := classifyAppError(store.MissingBindingItemError{ProjectRoot: projectRoot, Alias: "secret_01", ItemName: "TOKEN"})
	if classified == nil || classified.Code != errCodeNotFound || !strings.Contains(classified.Hint, "TOKEN") {
		t.Fatalf("missing binding classification = %+v", classified)
	}
}

func TestTargetRuntimeHelperCoverage(t *testing.T) {
	lockAppSeams(t)
	openVaultHandleFn = openVaultHandle
	projectRoot, starter := setupTargetRuntimeFixture(t)
	var stderr bytes.Buffer
	_ = runWithStarter(context.Background(), []string{"run", "--project-root", projectRoot, "--target", "missing", "--", "true"}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)
	_ = runWithStarter(context.Background(), []string{"run", "--project-root", projectRoot, "--target", "build.config", "--", "true"}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)
	_ = runWithStarter(context.Background(), []string{"run", "--project-root", projectRoot, "--target", "server.dev", "--dry-run", "--explain"}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)
	_ = runWithStarter(context.Background(), []string{"inject", "--project-root", projectRoot, "--target", "server.dev", "--", "true"}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)
	_ = runWithStarter(context.Background(), []string{"write-env", "--project-root", projectRoot, "--target", "server.dev", "--output", filepath.Join(t.TempDir(), ".env")}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)
	_ = runWithStarter(context.Background(), []string{"write-env", "--project-root", projectRoot, "--target", "missing", "--output", filepath.Join(t.TempDir(), ".env")}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)
	_ = runWithStarter(context.Background(), []string{"write-env", "--project-root", projectRoot, "--target", "release.sign", "--output", filepath.Join(t.TempDir(), ".env")}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)
	_ = runWithStarter(context.Background(), []string{"write-env", "--project-root", projectRoot, "--target", "server.dev", "--env", "X=@OPENAI_API_KEY", "--output", filepath.Join(t.TempDir(), ".env")}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)

	if err := warnTargetDrift(io.Discard, nil, projectRoot, store.ManifestTargetExpansion{}); err != nil {
		t.Fatalf("empty drift warning: %v", err)
	}
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	origDrift := manifestTargetDriftFn
	t.Cleanup(func() { manifestTargetDriftFn = origDrift })
	manifestTargetDriftFn = func(*store.Handle, string, store.ManifestTargetExpansion) (store.ManifestDrift, error) {
		return store.ManifestDrift{}, errors.New("drift fail")
	}
	if err := warnTargetDrift(io.Discard, handle, projectRoot, store.ManifestTargetExpansion{TargetName: "server.dev"}); err == nil {
		t.Fatal("expected drift warning error")
	}
	_ = runWithStarter(context.Background(), []string{
		"run", "--project-root", projectRoot, "--target", "server.dev",
		"--grant-project", "window", "--grant-secret", "session", "--grant-window", "15m", "--", "true",
	}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)
	_ = runWithStarter(context.Background(), []string{
		"write-env", "--project-root", projectRoot, "--target", "build.config",
		"--grant-project", "window", "--grant-secret", "session", "--grant-convenience", "window", "--grant-window", "15m",
	}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)
	manifestTargetDriftFn = origDrift
	manifestTargetDriftFn = func(*store.Handle, string, store.ManifestTargetExpansion) (store.ManifestDrift, error) {
		return store.ManifestDrift{Changed: true, OutputsChanged: true}, nil
	}
	if err := warnTargetDrift(io.Discard, handle, projectRoot, store.ManifestTargetExpansion{TargetName: "server.dev"}); err != nil {
		t.Fatalf("output-only drift warning: %v", err)
	}
	manifestTargetDriftFn = func(*store.Handle, string, store.ManifestTargetExpansion) (store.ManifestDrift, error) {
		return store.ManifestDrift{Changed: true}, nil
	}
	if err := warnTargetDrift(io.Discard, handle, projectRoot, store.ManifestTargetExpansion{TargetName: "server.dev"}); err != nil {
		t.Fatalf("generic drift warning: %v", err)
	}
	manifestTargetDriftFn = origDrift
	reviewTargetForTest(t, projectRoot, "server.dev")
	reviewTargetForTest(t, projectRoot, "build.config")
	origRecord := recordManifestReviewFn
	t.Cleanup(func() { recordManifestReviewFn = origRecord })
	recordManifestReviewFn = func(*store.Handle, string, store.ManifestTargetExpansion) error {
		return errors.New("record fail")
	}
	_ = runWithStarter(context.Background(), []string{
		"run", "--project-root", projectRoot, "--target", "server.dev",
		"--grant-project", "window", "--grant-secret", "session", "--grant-window", "15m", "--", "true",
	}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)
	_ = runWithStarter(context.Background(), []string{
		"write-env", "--project-root", projectRoot, "--target", "build.config",
		"--grant-project", "window", "--grant-secret", "session", "--grant-convenience", "window", "--grant-window", "15m",
	}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)
	recordManifestReviewFn = origRecord
	writeMixedTargetManifestForCoverage(t, projectRoot, true)
	_ = runWithStarter(context.Background(), []string{"write-env", "--project-root", projectRoot, "--target", "mixed"}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)
	writeMixedTargetManifestForCoverage(t, projectRoot, false)
	_ = runWithStarter(context.Background(), []string{"write-env", "--project-root", projectRoot, "--target", "mixed"}, bytes.NewBuffer(nil), io.Discard, &stderr, starter)

	for _, expansion := range []store.ManifestTargetExpansion{
		{TargetName: "none"},
		{TargetName: "dupe", Outputs: map[string]string{"A": "", "B": "out", "C": "out"}},
		{TargetName: "many", Outputs: map[string]string{"A": "a", "B": "b"}},
	} {
		_, _ = singleTargetOutput(expansion)
	}
	var explain bytes.Buffer
	if err := writeExplainText(&explain, explainPayload{Command: "run", Target: "server.dev", ManifestHash: "hash"}); err != nil {
		t.Fatalf("write explain text: %v", err)
	}
}

func TestApplyAppTargetConfigCoverage(t *testing.T) {
	openVaultHandleFn = openVaultHandle
	projectRoot, _ := setupTargetRuntimeFixture(t)
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if err := applyAppTargetConfig(context.Background(), handle, nil); err != nil {
		t.Fatalf("nil target config: %v", err)
	}
	if err := applyAppTargetConfig(context.Background(), handle, &appConnectConfig{Target: "server.dev"}); err == nil {
		t.Fatal("expected missing project root")
	}
	if err := applyAppTargetConfig(context.Background(), handle, &appConnectConfig{ProjectRoot: t.TempDir(), Target: "server.dev"}); err == nil {
		t.Fatal("expected missing manifest")
	}
	if err := applyAppTargetConfig(context.Background(), handle, &appConnectConfig{ProjectRoot: projectRoot, Target: "missing", Command: "true"}); err == nil {
		t.Fatal("expected unknown target")
	}
	if err := handle.RecordManifestTargetReview(projectRoot, mustExpandTargetForCoverage(t, projectRoot, "server.dev")); err != nil {
		t.Fatalf("review server.dev: %v", err)
	}
	cfg := &appConnectConfig{ProjectRoot: projectRoot, Target: "server.dev"}
	if err := applyAppTargetConfig(context.Background(), handle, cfg); err != nil {
		t.Fatalf("apply command/env target: %v", err)
	}
	if cfg.Command == "" || cfg.EnvMappings["OPENAI_API_KEY"] != "OPENAI_API_KEY" {
		t.Fatalf("unexpected applied target config: %+v", cfg)
	}
	if err := handle.RecordManifestTargetReview(projectRoot, mustExpandTargetForCoverage(t, projectRoot, "release.sign")); err != nil {
		t.Fatalf("review release.sign: %v", err)
	}
	fileCfg := &appConnectConfig{ProjectRoot: projectRoot, Target: "release.sign", Command: "true"}
	if err := applyAppTargetConfig(context.Background(), handle, fileCfg); err != nil {
		t.Fatalf("apply file target: %v", err)
	}
	if fileCfg.FileMappings["GOOGLE_APPLICATION_CREDENTIALS"] != "GOOGLE_SERVICE_ACCOUNT" {
		t.Fatalf("file mappings = %+v", fileCfg.FileMappings)
	}
	if err := handle.RecordManifestTargetReview(projectRoot, mustExpandTargetForCoverage(t, projectRoot, "build.config")); err != nil {
		t.Fatalf("review build.config: %v", err)
	}
	if err := applyAppTargetConfig(context.Background(), handle, &appConnectConfig{ProjectRoot: projectRoot, Target: "build.config", Command: "true"}); err == nil {
		t.Fatal("expected workspace-visible delivery error")
	}
	writeUnresolvedAppTargetManifestForCoverage(t, projectRoot)
	expansion, err := store.ExpandManifestTarget(projectRoot, "unresolved")
	if err != nil {
		t.Fatalf("expand unresolved target: %v", err)
	}
	if err := handle.RecordManifestTargetReview(projectRoot, expansion); err != nil {
		t.Fatalf("review unresolved target: %v", err)
	}
	if err := applyAppTargetConfig(context.Background(), handle, &appConnectConfig{ProjectRoot: projectRoot, Target: "unresolved", Command: "true"}); err == nil {
		t.Fatal("expected unresolved target ref")
	}
	fileExpansion, err := store.ExpandManifestTarget(projectRoot, "unresolved.file")
	if err != nil {
		t.Fatalf("expand unresolved file target: %v", err)
	}
	if err := handle.RecordManifestTargetReview(projectRoot, fileExpansion); err != nil {
		t.Fatalf("review unresolved file target: %v", err)
	}
	if err := applyAppTargetConfig(context.Background(), handle, &appConnectConfig{ProjectRoot: projectRoot, Target: "unresolved.file", Command: "true"}); err == nil {
		t.Fatal("expected unresolved file target ref")
	}
	writeNoCommandTargetManifestForCoverage(t, projectRoot)
	if err := handle.RecordManifestTargetReview(projectRoot, mustExpandTargetForCoverage(t, projectRoot, "no.command")); err != nil {
		t.Fatalf("review no.command: %v", err)
	}
	if err := applyAppTargetConfig(context.Background(), handle, &appConnectConfig{ProjectRoot: projectRoot, Target: "no.command"}); err == nil {
		t.Fatal("expected no command error")
	}
	if got := shellQuoteArg(""); got != "''" {
		t.Fatalf("empty quote = %q", got)
	}
	if got := shellQuoteArg("has space's"); got != "'has space'\"'\"'s'" {
		t.Fatalf("quote = %q", got)
	}
}

func mustExpandTargetForCoverage(t *testing.T, projectRoot string, targetName string) store.ManifestTargetExpansion {
	t.Helper()
	expansion, err := store.ExpandManifestTarget(projectRoot, targetName)
	if err != nil {
		t.Fatalf("expand target %s: %v", targetName, err)
	}
	return expansion
}

func writeNoCommandTargetManifestForCoverage(t *testing.T, projectRoot string) {
	t.Helper()
	body := `{
  "version":"v1",
  "references":[{"alias":"secret_01","item":"OPENAI_API_KEY"}],
  "requirements":[{"ref":"@OPENAI_API_KEY","kind":"kv","classification":"secret","required":true}],
  "targets":[{"name":"no.command","root":".","delivery":[{"as":"env","name":"OPENAI_API_KEY","ref":"@OPENAI_API_KEY"}]}]
}`
	if err := os.WriteFile(filepath.Join(projectRoot, ".hasp.manifest.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write no-command manifest: %v", err)
	}
}

func TestAuditTailAndPlaintextResidualCoverage(t *testing.T) {
	lockAppSeams(t)
	origLog := newAuditLogFn
	origEvents := auditEventsFn
	origGrant := grantPlaintextUseFn
	t.Cleanup(func() {
		newAuditLogFn = origLog
		auditEventsFn = origEvents
		grantPlaintextUseFn = origGrant
	})

	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	calls := 0
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) {
		calls++
		if calls == 1 {
			return nil, nil
		}
		return []audit.Event{{Sequence: 1, Type: "run", Timestamp: time.Now()}}, nil
	}
	if err := auditTailCommand(context.Background(), []string{"--follow", "--json"}, errWriter{err: errors.New("write fail")}, auditTailOpts{PollInterval: time.Millisecond}); err == nil {
		t.Fatal("expected follow render failure")
	}
	newAuditLogFn = origLog
	auditEventsFn = origEvents

	handle, _ := setupAgentSafeSession(t)
	grantPlaintextUseFn = func(*store.Handle, string, string, store.PlaintextAction, string, store.GrantScope, time.Duration) (store.PlaintextGrant, error) {
		return store.PlaintextGrant{}, errors.New("grant fail")
	}
	err := enforceSecretPlaintextPolicyInteractive(context.Background(), handle, "API_TOKEN", store.PlaintextReveal, nil, io.Discard, secretPlaintextDeps{
		Confirm: func(io.Writer, io.Reader, string) (bool, error) { return true, nil },
	})
	if err == nil || !strings.Contains(err.Error(), "grant fail") {
		t.Fatalf("expected plaintext grant failure, got %v", err)
	}
}

func writeMixedTargetManifestForCoverage(t *testing.T, projectRoot string, includeEnv bool) {
	t.Helper()
	delivery := `{"as":"xcconfig","name":"API_BASE_URL","ref":"@API_BASE_URL"}`
	if includeEnv {
		delivery += `,{"as":"env","name":"OPENAI_API_KEY","ref":"@OPENAI_API_KEY"}`
	}
	body := `{
  "version":"v1",
  "references":[
    {"alias":"config_01","item":"API_BASE_URL"},
    {"alias":"secret_01","item":"OPENAI_API_KEY"}
  ],
  "requirements":[
    {"ref":"@API_BASE_URL","kind":"kv","classification":"public_config","required":true},
    {"ref":"@OPENAI_API_KEY","kind":"kv","classification":"secret","required":true}
  ],
  "targets":[{"name":"mixed","root":".","delivery":[` + delivery + `]}]
}`
	if err := os.WriteFile(filepath.Join(projectRoot, ".hasp.manifest.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write mixed manifest: %v", err)
	}
}

func writeUnresolvedAppTargetManifestForCoverage(t *testing.T, projectRoot string) {
	t.Helper()
	body := `{
  "version":"v1",
  "references":[{"alias":"extra_01","item":"EXTRA_SECRET"},{"alias":"file_99","item":"EXTRA_FILE"}],
  "requirements":[
    {"ref":"extra_01","kind":"kv","classification":"secret","required":true},
    {"ref":"file_99","kind":"file","classification":"secret","required":true}
  ],
  "targets":[
    {"name":"unresolved","root":".","command":["true"],"delivery":[{"as":"env","name":"EXTRA_SECRET","ref":"extra_01"}]},
    {"name":"unresolved.file","root":".","command":["true"],"delivery":[{"as":"file","name":"EXTRA_FILE","ref":"file_99"}]}
  ]
}`
	if err := os.WriteFile(filepath.Join(projectRoot, ".hasp.manifest.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write unresolved manifest: %v", err)
	}
}

func projectCoverageManifest() store.RepoManifest {
	return store.RepoManifest{
		Version: "v1",
		References: []store.ManifestReference{
			{Alias: "secret_01", Item: "OPENAI_API_KEY"},
			{Alias: "file_01", Item: "GOOGLE_SERVICE_ACCOUNT"},
			{Alias: "config_01", Item: "API_BASE_URL"},
			{Alias: "unused_01", Item: "UNUSED_SECRET"},
		},
		Requirements: []store.ManifestRequirement{
			{Ref: "secret_01", Kind: store.ItemKindKV, Classification: store.ManifestClassificationSecret, Required: true},
			{Ref: "file_01", Kind: store.ItemKindFile, Classification: store.ManifestClassificationSecret, Required: true},
			{Ref: "config_01", Kind: store.ItemKindKV, Classification: store.ManifestClassificationPublicConfig, Required: true},
			{Ref: "unused_01", Kind: store.ItemKindKV, Classification: store.ManifestClassificationSecret, Required: false},
		},
		Targets: []store.ManifestTarget{{
			Name:    "server.dev",
			Root:    "apps/server",
			Command: []string{"sh", "-c", "true"},
			Delivery: []store.ManifestDelivery{
				{As: store.ManifestDeliveryEnv, Name: "OPENAI_API_KEY", Ref: "secret_01"},
				{As: store.ManifestDeliveryEnv, Name: "OPENAI_API_KEY_COPY", Ref: "secret_01"},
				{As: store.ManifestDeliveryFile, Name: "GOOGLE_APPLICATION_CREDENTIALS", Ref: "file_01"},
				{As: store.ManifestDeliveryXCConfig, Name: "API_BASE_URL", Ref: "config_01", Output: "apps/server/Config/Secrets.generated.xcconfig"},
				{As: store.ManifestDeliveryEnv, Name: "EMPTY_REF"},
			},
			Examples: []store.ManifestExample{
				{Format: store.ManifestExampleEnv, Path: "apps/server/.env.example"},
				{Format: store.ManifestExampleXCConfig, Path: "apps/server/Config/Secrets.example.xcconfig"},
			},
		}},
	}
}
