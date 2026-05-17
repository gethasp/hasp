package profiles

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLoadSupportStatuses(t *testing.T) {
	origCatalog := loadSupportCatalogFn
	origGates := loadSupportGatesFn
	defer func() {
		loadSupportCatalogFn = origCatalog
		loadSupportGatesFn = origGates
	}()
	supportStatusCache = sync.Map{}
	statuses, err := LoadSupportStatuses()
	if err != nil {
		t.Fatalf("load support statuses: %v", err)
	}
	if len(statuses) != 7 {
		t.Fatalf("support statuses = %d, want 7", len(statuses))
	}
	for _, status := range statuses {
		if status.SupportTier != SupportTierFirstClassShipped {
			t.Fatalf("unexpected support tier for %s: %+v", status.Profile.ID, status)
		}
		if !status.FirstClass {
			t.Fatalf("expected first-class support for %s", status.Profile.ID)
		}
		if status.CompatibilityLabel != CompatibilityLabelFirstClass {
			t.Fatalf("unexpected compatibility label for %s: %q", status.Profile.ID, status.CompatibilityLabel)
		}
		for _, key := range []string{"release_gate", "docs", "fixture", "evals", "benchmarks", "support_tier"} {
			if status.Proof[key].Status == "" {
				t.Fatalf("missing proof %q for %s: %+v", key, status.Profile.ID, status.Proof)
			}
		}
	}
	cached, err := LoadSupportStatuses()
	if err != nil {
		t.Fatalf("load cached support statuses: %v", err)
	}
	cached[0].Proof["docs"] = SupportCheck{Status: "mutated"}
	reloaded, err := LoadSupportStatuses()
	if err != nil {
		t.Fatalf("reload cached support statuses: %v", err)
	}
	if reloaded[0].Proof["docs"].Status == "mutated" {
		t.Fatal("expected cached support statuses to be cloned")
	}

	supportStatusCache = sync.Map{}
	loadSupportCatalogFn = func() ([]Profile, error) { return nil, errors.New("catalog fail") }
	if _, err := LoadSupportStatuses(); err == nil || !strings.Contains(err.Error(), "catalog fail") {
		t.Fatalf("expected top-level LoadSupportStatuses error, got %v", err)
	}
}

func TestLoadSupportStatusByIDAndFailures(t *testing.T) {
	origCatalog := loadSupportCatalogFn
	origGates := loadSupportGatesFn
	defer func() {
		loadSupportCatalogFn = origCatalog
		loadSupportGatesFn = origGates
	}()
	supportStatusCache = sync.Map{}
	status, err := LoadSupportStatus("claude-code")
	if err != nil {
		t.Fatalf("load support status by id: %v", err)
	}
	if status.Profile.ID != "claude-code" {
		t.Fatalf("unexpected support status: %+v", status)
	}
	if _, err := LoadSupportStatus("missing"); err == nil {
		t.Fatal("expected missing support status failure")
	}
	if _, err := loadSupportStatusesWith(func() ([]Profile, error) {
		return nil, errors.New("catalog fail")
	}, LoadReleaseGates); err == nil || !strings.Contains(err.Error(), "catalog fail") {
		t.Fatalf("expected catalog failure, got %v", err)
	}
	if _, err := loadSupportStatusesWith(LoadCatalog, func() (ReleaseGateManifest, error) {
		return ReleaseGateManifest{}, errors.New("gates fail")
	}); err == nil || !strings.Contains(err.Error(), "gates fail") {
		t.Fatalf("expected gates failure, got %v", err)
	}
	if _, err := loadSupportStatusWith(func() ([]Profile, error) {
		return nil, errors.New("catalog fail")
	}, LoadReleaseGates, "claude-code"); err == nil || !strings.Contains(err.Error(), "catalog fail") {
		t.Fatalf("expected loadSupportStatusWith catalog failure, got %v", err)
	}
	if _, err := loadSupportStatusWith(func() ([]Profile, error) {
		return []Profile{{ID: "other"}}, nil
	}, LoadReleaseGates, "claude-code"); err == nil {
		t.Fatal("expected loadSupportStatusWith missing id failure")
	}
	supportStatusCache = sync.Map{}
	loadSupportCatalogFn = func() ([]Profile, error) { return nil, errors.New("catalog fail") }
	if _, err := LoadSupportStatus("claude-code"); err == nil || !strings.Contains(err.Error(), "catalog fail") {
		t.Fatalf("expected top-level LoadSupportStatus error, got %v", err)
	}
	status, err = loadSupportStatusWith(func() ([]Profile, error) {
		return []Profile{{ID: "claude-code"}}, nil
	}, func() (ReleaseGateManifest, error) {
		return ReleaseGateManifest{}, nil
	}, "claude-code")
	if err != nil || status.Profile.ID != "claude-code" {
		t.Fatalf("expected loadSupportStatusWith success, got status=%+v err=%v", status, err)
	}
}

func TestBuildSupportStatusDowngradesBrokenProof(t *testing.T) {
	profile := Profile{
		ID:                   "generic",
		Name:                 "Generic",
		Transport:            "cli-or-mcp",
		Command:              []string{"hasp", "mcp"},
		ProjectBindingRecipe: "bind",
		ApprovalPath:         "approve",
		SafeInjectPath:       "safe",
		WriteEnvPath:         "write-env",
		RegressionFixture:    "does/not/exist.json",
		DocsPath:             "docs/agent-profiles/README.md",
	}
	status := buildSupportStatus(profile, ReleaseGateManifest{
		RequiredDocSections: []string{"## Missing"},
		Profiles:            map[string]ReleaseGate{},
	})
	if status.FirstClass {
		t.Fatalf("expected broken proof to downgrade first-class support: %+v", status)
	}
	if status.SupportTier != SupportTierGenericCompatible {
		t.Fatalf("unexpected downgraded support tier: %+v", status)
	}
	if status.CompatibilityLabel != CompatibilityLabelGeneric {
		t.Fatalf("unexpected downgraded compatibility label: %+v", status)
	}
	if status.Proof["release_gate"].Status != "fail" || status.Proof["support_tier"].Status != "warn" {
		t.Fatalf("unexpected downgraded proof: %+v", status.Proof)
	}

	profile = Profile{
		ID:                   "claude-code",
		Name:                 "Claude Code",
		Transport:            "mcp-stdio",
		Command:              []string{"hasp", "mcp"},
		ProjectBindingRecipe: "bind",
		ApprovalPath:         "approve",
		SafeInjectPath:       "safe",
		WriteEnvPath:         "write-env",
		RegressionFixture:    "apps/server/testdata/profiles/claude-code.json",
		DocsPath:             "docs/agent-profiles/claude-code.md",
	}
	status = buildSupportStatus(profile, ReleaseGateManifest{
		RequiredDocSections: []string{"## Config Example"},
		Profiles: map[string]ReleaseGate{
			"claude-code": {
				EvalTests: []string{"TestDoesNotExist"},
				Benchmarks: []BenchmarkSuite{{
					Package:   "./internal/mcp",
					Functions: []string{"BenchmarkDoesNotExist"},
				}},
			},
		},
	})
	if status.Proof["evals"].Status != "fail" || status.Proof["benchmarks"].Status != "fail" {
		t.Fatalf("expected failing eval/benchmark proof, got %+v", status.Proof)
	}
}

func TestSupportStatusCacheKey(t *testing.T) {
	temp := t.TempDir()
	profilesDir := filepath.Join(temp, "apps", "server", "profiles")
	if err := os.MkdirAll(profilesDir, 0o755); err != nil {
		t.Fatalf("mkdir profiles dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(temp, "VERSION"), []byte("1"), 0o600); err != nil {
		t.Fatalf("write version: %v", err)
	}
	t.Setenv(envProfilesDir, profilesDir)
	t.Chdir(t.TempDir())

	key, err := supportStatusCacheKey()
	if err != nil || !strings.Contains(key, profilesDir) {
		t.Fatalf("unexpected support status cache key %q err=%v", key, err)
	}

	t.Setenv(envProfilesDir, filepath.Join(t.TempDir(), "missing"))
	if _, err := supportStatusCacheKey(); err == nil {
		t.Fatal("expected supportStatusCacheKey error when catalog dir is unavailable")
	}

	noRootProfiles := filepath.Join(t.TempDir(), "profiles")
	if err := os.MkdirAll(noRootProfiles, 0o755); err != nil {
		t.Fatalf("mkdir no-root profiles: %v", err)
	}
	t.Setenv(envProfilesDir, noRootProfiles)
	t.Chdir(t.TempDir())
	key, err = supportStatusCacheKey()
	if err != nil || !strings.HasPrefix(key, "|") {
		t.Fatalf("expected supportStatusCacheKey to fall back to empty root, got %q err=%v", key, err)
	}
}
