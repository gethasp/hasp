package profiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadProfilesCatalog(t *testing.T) {
	repoRoot, err := repoRoot()
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	profilesDir := filepath.Join(repoRoot, "apps", "server", "profiles")
	profiles, err := LoadDir(profilesDir)
	if err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	manifest, err := LoadReleaseGatesFrom(filepath.Join(profilesDir, releaseGateFilename))
	if err != nil {
		t.Fatalf("load release gates: %v", err)
	}
	if len(profiles) != 7 {
		t.Fatalf("profiles = %d, want 7", len(profiles))
	}
	for _, profile := range profiles {
		gate, ok := manifest.Profiles[profile.ID]
		if !ok {
			t.Fatalf("release gate missing for %s", profile.ID)
		}
		docsPath := filepath.Join(repoRoot, profile.DocsPath)
		if _, err := os.Stat(docsPath); err != nil {
			t.Fatalf("docs path missing for %s: %v", profile.ID, err)
		}
		if _, err := os.Stat(filepath.Join(repoRoot, profile.RegressionFixture)); err != nil {
			t.Fatalf("fixture path missing for %s: %v", profile.ID, err)
		}
		data, err := os.ReadFile(docsPath)
		if err != nil {
			t.Fatalf("read docs for %s: %v", profile.ID, err)
		}
		for _, section := range manifest.RequiredDocSections {
			if !strings.Contains(string(data), section) {
				t.Fatalf("docs for %s missing required section %q", profile.ID, section)
			}
		}
		if err := verifyEvalTests(gate); err != nil {
			t.Fatalf("eval coverage for %s: %v", profile.ID, err)
		}
		if err := verifyBenchmarkSuites(gate); err != nil {
			t.Fatalf("benchmark coverage for %s: %v", profile.ID, err)
		}
	}
}
