package profiles

import (
	"path/filepath"
	"testing"
)

func TestFindProfilesDirAndLoadDefault(t *testing.T) {
	dir, err := CatalogDir()
	if err != nil {
		t.Fatalf("find profiles dir: %v", err)
	}
	if filepath.Base(dir) != "profiles" {
		t.Fatalf("unexpected profiles dir: %s", dir)
	}
	profiles, err := LoadCatalog()
	if err != nil {
		t.Fatalf("load default profiles: %v", err)
	}
	if len(profiles) != 7 {
		t.Fatalf("profiles = %d, want 7", len(profiles))
	}
}

func TestLoadDefaultByIDAndReleaseGates(t *testing.T) {
	profile, err := LoadProfile("claude-code")
	if err != nil {
		t.Fatalf("load profile by id: %v", err)
	}
	if profile.Name != "Claude Code" {
		t.Fatalf("unexpected profile: %+v", profile)
	}
	if _, err := LoadProfile("missing"); err == nil {
		t.Fatal("expected missing profile failure")
	}

	gates, err := LoadReleaseGates()
	if err != nil {
		t.Fatalf("load release gates: %v", err)
	}
	if len(gates.Profiles) != 7 {
		t.Fatalf("release gates = %d, want 7", len(gates.Profiles))
	}
	gate, err := ReleaseGateForProfile("claude-code")
	if err != nil {
		t.Fatalf("find release gate: %v", err)
	}
	if len(gate.EvalTests) == 0 || len(gate.Benchmarks) == 0 {
		t.Fatalf("expected release gate coverage metadata: %+v", gate)
	}
	if _, err := ReleaseGateForProfile("missing"); err == nil {
		t.Fatal("expected missing release gate failure")
	}
}

func TestReleaseGatesCoverAllProfiles(t *testing.T) {
	profiles, err := LoadCatalog()
	if err != nil {
		t.Fatalf("load default profiles: %v", err)
	}
	manifest, err := LoadReleaseGates()
	if err != nil {
		t.Fatalf("load release gates: %v", err)
	}
	if len(manifest.RequiredDocSections) == 0 {
		t.Fatal("required doc sections must not be empty")
	}
	for _, profile := range profiles {
		gate, ok := manifest.Profiles[profile.ID]
		if !ok {
			t.Fatalf("missing release gate for %s", profile.ID)
		}
		if len(gate.EvalTests) == 0 {
			t.Fatalf("missing eval coverage declaration for %s", profile.ID)
		}
		if len(gate.Benchmarks) == 0 {
			t.Fatalf("missing benchmark coverage declaration for %s", profile.ID)
		}
		if err := verifyDocsSections(profile, manifest.RequiredDocSections); err != nil {
			t.Fatalf("verify docs for %s: %v", profile.ID, err)
		}
		if _, err := LoadRegressionFixture(profile); err != nil {
			t.Fatalf("load regression fixture for %s: %v", profile.ID, err)
		}
		if err := verifyEvalTests(gate); err != nil {
			t.Fatalf("verify eval tests for %s: %v", profile.ID, err)
		}
		if err := verifyBenchmarkSuites(gate); err != nil {
			t.Fatalf("verify benchmark suites for %s: %v", profile.ID, err)
		}
	}
	for id := range manifest.Profiles {
		if _, err := LoadProfile(id); err != nil {
			t.Fatalf("release gate profile %s missing from catalog: %v", id, err)
		}
	}
}
