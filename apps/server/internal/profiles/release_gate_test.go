package profiles

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadReleaseGatesFromRejectsMissingAndMalformedFiles(t *testing.T) {
	if _, err := LoadReleaseGatesFrom(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected missing release gate file error")
	}

	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write malformed file: %v", err)
	}
	if _, err := LoadReleaseGatesFrom(path); err == nil {
		t.Fatal("expected malformed release gate decode error")
	}
}

func TestReleaseGateManifestValidateRejectsMissingFields(t *testing.T) {
	cases := []ReleaseGateManifest{
		{},
		{RequiredDocSections: []string{"## Config Example"}},
		{Profiles: map[string]ReleaseGate{"claude-code": {EvalTests: []string{"TestX"}}}},
		{
			RequiredDocSections: []string{"## Config Example"},
			Profiles: map[string]ReleaseGate{
				"claude-code": {EvalTests: []string{"TestX"}},
			},
		},
		{
			RequiredDocSections: []string{"## Config Example"},
			Profiles: map[string]ReleaseGate{
				" ": {
					EvalTests: []string{"TestX"},
					Benchmarks: []BenchmarkSuite{{
						Package:   "./internal/mcp",
						Functions: []string{"BenchmarkToolsList"},
					}},
				},
			},
		},
		{
			RequiredDocSections: []string{"## Config Example"},
			Profiles: map[string]ReleaseGate{
				"claude-code": {
					EvalTests: []string{"TestX"},
					Benchmarks: []BenchmarkSuite{{
						Package:   " ",
						Functions: []string{"BenchmarkToolsList"},
					}},
				},
			},
		},
		{
			RequiredDocSections: []string{"## Config Example"},
			Profiles: map[string]ReleaseGate{
				"claude-code": {
					EvalTests: []string{"TestX"},
					Benchmarks: []BenchmarkSuite{{
						Package: "./internal/mcp",
					}},
				},
			},
		},
	}
	for _, manifest := range cases {
		if err := manifest.Validate(); err == nil {
			t.Fatalf("expected validation failure for %+v", manifest)
		}
	}
}

func TestLoadRegressionFixture(t *testing.T) {
	profile := Profile{
		ID:                "claude-code",
		RegressionFixture: "apps/server/testdata/profiles/claude-code.json",
	}
	fixture, err := LoadRegressionFixture(profile)
	if err != nil {
		t.Fatalf("load regression fixture: %v", err)
	}
	if fixture.Tool != "hasp_list" {
		t.Fatalf("unexpected tool: %+v", fixture)
	}
}

func TestReleaseGateHelpersAndFailures(t *testing.T) {
	catalog, err := LoadCatalog()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	if len(catalog) != 6 {
		t.Fatalf("catalog len = %d", len(catalog))
	}
	if _, err := LoadProfile("missing"); err == nil {
		t.Fatal("expected missing profile error")
	}

	manifest, err := LoadReleaseGates()
	if err != nil {
		t.Fatalf("load release gates: %v", err)
	}
	if len(manifest.Profiles) == 0 || len(manifest.RequiredDocSections) == 0 {
		t.Fatalf("unexpected release gate manifest: %+v", manifest)
	}
	if _, err := ReleaseGateForProfile("missing"); err == nil {
		t.Fatal("expected missing release gate error")
	}

	if err := verifyDocsSections(Profile{ID: "claude-code", DocsPath: "docs/agent-profiles/claude-code.md"}, manifest.RequiredDocSections); err != nil {
		t.Fatalf("verify docs sections: %v", err)
	}
	if err := verifyDocsSections(Profile{ID: "bad", DocsPath: "docs/agent-profiles/README.md"}, []string{"## Missing"}); err == nil {
		t.Fatal("expected missing docs section failure")
	}

	gate, err := ReleaseGateForProfile("claude-code")
	if err != nil {
		t.Fatalf("release gate for profile: %v", err)
	}
	if err := verifyBenchmarkSuites(gate); err != nil {
		t.Fatalf("verify benchmark suites: %v", err)
	}
	if err := verifyEvalTests(gate); err != nil {
		t.Fatalf("verify eval tests: %v", err)
	}

	badGate := ReleaseGate{
		EvalTests: []string{"TestMissingEval"},
		Benchmarks: []BenchmarkSuite{{
			Package:   "./internal/mcp",
			Functions: []string{"BenchmarkMissing"},
		}},
	}
	if err := verifyBenchmarkSuites(badGate); err == nil {
		t.Fatal("expected missing benchmark failure")
	}
	if err := verifyEvalTests(badGate); err == nil {
		t.Fatal("expected missing eval failure")
	}

	badFixturePath := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(badFixturePath, []byte(`{"tool":""}`), 0o600); err != nil {
		t.Fatalf("write bad fixture: %v", err)
	}
	if _, err := LoadRegressionFixture(Profile{RegressionFixture: badFixturePath}); err == nil {
		t.Fatal("expected missing tool fixture failure")
	}

	malformedPath := filepath.Join(t.TempDir(), "release-gates.json")
	data, err := json.Marshal(ReleaseGateManifest{
		RequiredDocSections: []string{"## Config Example"},
		Profiles: map[string]ReleaseGate{
			"bad": {},
		},
	})
	if err != nil {
		t.Fatalf("marshal malformed manifest: %v", err)
	}
	if err := os.WriteFile(malformedPath, data, 0o600); err != nil {
		t.Fatalf("write malformed manifest: %v", err)
	}
	if _, err := LoadReleaseGatesFrom(malformedPath); err == nil {
		t.Fatal("expected manifest validation failure")
	}

	if _, err := loadReleaseGatesFS(os.DirFS(t.TempDir()), "."); err == nil {
		t.Fatal("expected fs release-gate read failure")
	}
	if _, err := decodeReleaseGates("source", []byte("{bad json")); err == nil {
		t.Fatal("expected decode failure")
	}
	if _, err := loadProfileWith(func() ([]Profile, error) { return nil, errors.New("load fail") }, "claude-code"); err == nil {
		t.Fatal("expected loadProfileWith loader failure")
	}
	if _, err := releaseGateForProfileWith(func() (ReleaseGateManifest, error) { return ReleaseGateManifest{}, errors.New("gate fail") }, "claude-code"); err == nil {
		t.Fatal("expected releaseGateForProfileWith loader failure")
	}
}

func TestReleaseGatePathAndDecodeFailures(t *testing.T) {
	if _, err := LoadRegressionFixture(Profile{RegressionFixture: "does/not/exist.json"}); err == nil {
		t.Fatal("expected regression fixture resolve failure")
	}

	absMissing := filepath.Join(t.TempDir(), "missing.json")
	if _, err := LoadRegressionFixture(Profile{RegressionFixture: absMissing}); err == nil {
		t.Fatal("expected regression fixture read failure")
	}

	badFixturePath := filepath.Join(t.TempDir(), "bad-fixture.json")
	if err := os.WriteFile(badFixturePath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write bad fixture json: %v", err)
	}
	if _, err := LoadRegressionFixture(Profile{RegressionFixture: badFixturePath}); err == nil {
		t.Fatal("expected regression fixture decode failure")
	}

	if err := verifyDocsSections(Profile{ID: "missing", DocsPath: "does/not/exist.md"}, []string{"## Config Example"}); err == nil {
		t.Fatal("expected docs path resolution failure")
	}

	absMissingDocs := filepath.Join(t.TempDir(), "missing.md")
	if err := verifyDocsSections(Profile{ID: "missing", DocsPath: absMissingDocs}, []string{"## Config Example"}); err == nil {
		t.Fatal("expected docs read failure")
	}

	profile, err := LoadProfile("claude-code")
	if err != nil {
		t.Fatalf("load profile for contract status: %v", err)
	}
	gate, err := ReleaseGateForProfile("claude-code")
	if err != nil {
		t.Fatalf("release gate for contract status: %v", err)
	}
	manifest, err := LoadReleaseGates()
	if err != nil {
		t.Fatalf("load release gates for contract status: %v", err)
	}
	status := ContractStatusForProfile(profile, gate, manifest.RequiredDocSections)
	if !status.Ready || !status.ReleaseGate.OK || !status.Docs.OK || !status.RegressionFixture.OK || !status.Benchmarks.OK || !status.Evals.OK {
		t.Fatalf("unexpected contract status: %+v", status)
	}
	failed := ContractStatusForProfile(profile, ReleaseGate{}, []string{"## Missing"})
	if failed.Ready || failed.ReleaseGate.Detail == "" || failed.Docs.Detail == "" {
		t.Fatalf("expected failed contract status, got %+v", failed)
	}
	if ok := contractCheck(nil, "ok"); !ok.OK || ok.Detail != "ok" {
		t.Fatalf("unexpected passing contract check: %+v", ok)
	}
	if failedCheck := contractCheck(errors.New("boom"), "ok"); failedCheck.OK || failedCheck.Detail != "boom" {
		t.Fatalf("unexpected failing contract check: %+v", failedCheck)
	}
}
